import os.path
import time
import re
import shutil
import stat
import tempfile
from contextlib import contextmanager
from fcntl import flock, LOCK_EX, LOCK_NB
import magic
from io import SEEK_END
from flask import request, jsonify, abort

from .. import app
from ..helpers import verify_token, gen_hash
from ..models import UploadedFile, ChunkedUpload


SHA256_RE = re.compile(r'[0-9a-f]{64}')


def _upload_id():
    checksum = request.form['id']
    if not SHA256_RE.fullmatch(checksum):
        abort(400)
    return checksum


@contextmanager
def _upload_lock(checksum, wait=True):
    lock_dir = os.path.join(app.config['FILE_STORAGE'], 'upload-locks', checksum[:2])
    os.makedirs(lock_dir, exist_ok=True)
    # Keep the lock file so concurrent workers always lock the same inode.
    # Closing the descriptor (including on worker exit) releases the lock.
    with open(os.path.join(lock_dir, checksum[2:]), 'a+b') as lock:
        try:
            flock(lock, LOCK_EX if wait else LOCK_EX | LOCK_NB)
        except BlockingIOError:
            yield None
        else:
            yield lock


def _chunk_dir(checksum):
    return os.path.join(app.config['FILE_STORAGE'], 'chunks', checksum)


def _get_upload(checksum):
    upload = ChunkedUpload.objects(id=checksum).first()
    if upload is None:
        abort(404)
    return upload


def _fingerprint(info):
    return '%s:%s:%s' % (info.st_ino, info.st_mtime_ns, info.st_ctime_ns)


def _cached_fingerprint(lock):
    lock.seek(0)
    return lock.read(128).decode('ascii', errors='ignore')


def _cache_fingerprint(lock, fingerprint):
    # Keep the cache on disk so old MongoEngine models can still read every record.
    lock.seek(0)
    lock.truncate()
    lock.write(fingerprint.encode('ascii'))
    lock.flush()


def _verified_file(path, size, checksum, verified=None):
    try:
        info = os.stat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size != size:
            return None
        fingerprint = _fingerprint(info)
        # An unchanged file has already passed the full SHA-256 check.
        if fingerprint == verified:
            return fingerprint
        with open(path, 'rb') as stream:
            if gen_hash(stream, 'sha256', read_size=1024 * 1024) == checksum:
                if _fingerprint(os.stat(path)) == fingerprint:
                    return fingerprint
    except FileNotFoundError:
        pass
    return None


def _published_record(upload, lock, metadata=None):
    record = UploadedFile.objects(checksum=upload.id).first()
    if record and record.expires == -1 and record.storage == 'cold':
        # A cold object is served by its configured remote mirror.
        return record if record.filesize == upload.filesize else None

    if record is None:
        record = UploadedFile(checksum=upload.id, expires=-1, filesize=upload.filesize)
        if metadata is not None:
            record.content_checksum = metadata.get('content_checksum')
            record.vp_checksum = metadata.get('vp_checksum')
        record.gen_filename()
    elif record.expires != -1:
        record.expires = -1
        record.gen_filename()

    path = os.path.join(app.config['FILE_STORAGE'], record.filename)
    cached = _cached_fingerprint(lock)
    verified = _verified_file(path, upload.filesize, upload.id, cached)
    if verified is None:
        return None

    record.filesize = upload.filesize
    record.save()
    if verified != cached:
        _cache_fingerprint(lock, verified)
    return record


def _set_upload_done(upload):
    if not upload.done:
        upload.done = True
        upload.save()

    try:
        shutil.rmtree(_chunk_dir(upload.id))
    except FileNotFoundError:
        pass
    except OSError:
        app.logger.exception('Failed to clean up chunks for upload %s', upload.id)


def _reset_lost_upload(upload):
    if upload.done:
        app.logger.error('Multipart upload %s was marked complete but has no valid published file', upload.id)
        upload.done = False
        upload.finished_parts = []
        upload.save()


def checked_upload_record(record):
    if record:
        upload = ChunkedUpload.objects(id=record.checksum).first()
        if upload:
            with _upload_lock(upload.id) as lock:
                return _published_record(upload, lock)
    return record


@app.route('/api/1/upload/check', methods={'POST'})
def check_uploaded():
    user = verify_token()
    if not user:
        abort(403)

    if 'content_checksum' in request.form:
        if 'is_vp' not in request.form:
            return jsonify(result=False)

        cond = {'content_checksum': request.form['content_checksum'], 'duplicate_of': None, 'is_vp': request.form['is_vp']}

        #if request.form['is_vp']:
        #    cond['vp_checksum__ne'] = None
        #else:
        #    cond['vp_checksum'] = None

        file = UploadedFile.objects(**cond).first()
    else:
        file = UploadedFile.objects(checksum=request.form['checksum']).first()

    file = checked_upload_record(file)
    if file:
        return jsonify(result=True, checksum=file.checksum, filesize=file.filesize, vp_checksum=file.vp_checksum, is_vp=file.is_vp)
    else:
        return jsonify(result=False)


@app.route('/api/1/upload/check_archive', methods={'POST'})
def check_uploaded_archive():
    user = verify_token()
    if not user:
        abort(403)

    #if 


@app.route('/api/1/upload/file', methods={'POST'})
def upload_file():
    user = verify_token()
    if not user:
        abort(403)

    if 'checksum' not in request.form or 'file' not in request.files:
        abort(400)

    file = request.files['file']
    checksum = request.form['checksum']
    if gen_hash(file.stream, 'sha256') != checksum:
        return jsonify(result=False, reason='checksum')

    file.seek(0)
    mime = magic.from_buffer(file.read(1024), mime=True)
    if mime in app.config['MIME_BLACKLIST']:
        return jsonify(result=False, reason='invalid mime')

    file.seek(0, SEEK_END)
    record = UploadedFile(expires=time.time() + 24 * 60 * 60,
                          checksum=checksum,
                          content_checksum=request.form.get('content_checksum'),
                          vp_checksum=request.form.get('vp_checksum'),
                          filesize=file.tell())

    if mime in ('image/jpg', 'image/jpeg'):
        record.file_ext = 'jpg'
    elif mime == 'image/png':
        record.file_ext = 'png'
    elif mime == 'image/x-ms-bmp':
        record.file_ext = 'bmp'

    # currently broken
    if False:  # record.content_checksum:
        duplicate = UploadedFile.objects(content_checksum=record.content_checksum, vp_checksum__ne=None, duplicate_of=None).first()
        if duplicate:
            record.duplicate_of = duplicate.checksum
            app.logger.warning('UploadedFile %s is a duplicate of %s!' % (record.checksum, duplicate.checksum))

    with _upload_lock(checksum) as lock:
        existing = UploadedFile.objects(checksum=checksum).first()
        if existing and existing.expires == -1:
            if existing.storage == 'cold':
                return jsonify(result=True)
            record = existing
            record.filesize = file.tell()
        else:
            record.gen_filename()

        full_path = os.path.join(app.config['FILE_STORAGE'], record.filename)
        if _verified_file(full_path, record.filesize, checksum, _cached_fingerprint(lock)) is None:
            temp_dir = os.path.join(app.config['FILE_STORAGE'], 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with tempfile.TemporaryDirectory(dir=temp_dir) as work_dir:
                source = os.path.join(work_dir, 'file')
                file.seek(0)
                file.save(source)
                os.replace(source, full_path)
        record.save()

    return jsonify(result=True)


@app.route('/api/1/multiupload/start', methods={'POST'})
def start_chunked_upload():
    user = verify_token()
    if not user:
        abort(403)

    checksum = _upload_id()
    size = request.form.get('size', type=int)
    parts = request.form.get('parts', type=int)
    if size is None or size < 0 or parts is None or parts < 0 or bool(size) != bool(parts):
        abort(400)

    with _upload_lock(checksum, wait=False) as lock:
        if lock:
            return _start_upload(checksum, size, parts, lock)
        upload = ChunkedUpload.objects(id=checksum).first()
        if upload:
            return jsonify(result=True, done=False, finished_parts=upload.finished_parts)

    # Two first-time start requests may arrive before either has registered the upload.
    with _upload_lock(checksum) as lock:
        return _start_upload(checksum, size, parts, lock)


def _start_upload(checksum, size, parts, lock):
    upload = ChunkedUpload.objects(id=checksum).first()
    if upload is None:
        upload = ChunkedUpload(id=checksum, filesize=size, total_parts=parts,
                               expires=time.time() + 24 * 60 * 60)
        upload.save()
    if upload.filesize != size:
        return jsonify(result=False, done=False, reason='upload size mismatch')

    if _published_record(upload, lock):
        _set_upload_done(upload)
        return jsonify(result=True, done=True, finished_parts=upload.finished_parts)

    _reset_lost_upload(upload)
    if upload.total_parts != parts:
        return jsonify(result=False, done=False, reason='upload part count mismatch')

    chunk_dir = _chunk_dir(checksum)
    os.makedirs(chunk_dir, exist_ok=True)
    available = [part for part in upload.finished_parts
                 if os.path.isfile(os.path.join(chunk_dir, str(part)))]
    if available != upload.finished_parts:
        upload.finished_parts = available
        upload.save()
    return jsonify(result=True, done=False, finished_parts=available)

@app.route('/api/1/multiupload/finish', methods={'POST'})
def finish_chunked_upload():
    user = verify_token()
    if not user:
        abort(403)

    checksum = _upload_id()
    if request.form['checksum'] != checksum:
        abort(400)

    with _upload_lock(checksum, wait=False) as lock:
        if not lock:
            # Knossos 1.3 treats this as a missing finish reply and polls start.
            return jsonify(result=False, reason='upload busy'), 503, {'Retry-After': '2'}
        upload = _get_upload(checksum)
        if _published_record(upload, lock, request.form) is None:
            _reset_lost_upload(upload)
            error = _assemble_upload(upload, request.form, lock)
            if error:
                return jsonify(result=False, reason=error)

        _set_upload_done(upload)
        app.logger.info('Finished upload for %s', checksum)
        return jsonify(result=True)


def _assemble_upload(upload, metadata, lock):
    chunk_dir = _chunk_dir(upload.id)
    os.makedirs(chunk_dir, exist_ok=True)
    # Remove temporary files left behind if the previous worker died.
    for name in os.listdir(chunk_dir):
        if name.startswith(('assembly-', 'part-')):
            shutil.rmtree(os.path.join(chunk_dir, name))

    record = UploadedFile.objects(checksum=upload.id).first()
    if record is None:
        record = UploadedFile(checksum=upload.id)
    if record.expires != -1:
        record.expires = -1
        record.gen_filename()
    record.filesize = upload.filesize
    record.content_checksum = metadata.get('content_checksum') or record.content_checksum
    record.vp_checksum = metadata.get('vp_checksum') or record.vp_checksum
    record.storage = None
    record.validate()

    with tempfile.TemporaryDirectory(prefix='assembly-', dir=chunk_dir) as work_dir:
        source = os.path.join(work_dir, 'file')
        with open(source, 'wb') as output:
            for part in range(upload.total_parts):
                try:
                    chunk = open(os.path.join(chunk_dir, str(part)), 'rb')
                except FileNotFoundError:
                    upload.update(pull__finished_parts=part)
                    return 'part missing'
                with chunk:
                    shutil.copyfileobj(chunk, output, 1024 * 1024)

        if _verified_file(source, upload.filesize, upload.id) is None:
            upload.update(set__finished_parts=[])
            return 'checksum fail'

        # Publish only closed, verified bytes, in one rename on FILE_STORAGE.
        dest = os.path.join(app.config['FILE_STORAGE'], record.filename)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        os.replace(source, dest)
        record.save()
        _cache_fingerprint(lock, _fingerprint(os.stat(dest)))


@app.route('/api/1/multiupload/part', methods={'POST'})
def upload_chunk():
    user = verify_token()
    if not user:
        abort(403)

    checksum = _upload_id()
    part = request.files['file']
    with _upload_lock(checksum):
        upload = _get_upload(checksum)
        idx = _part_index(upload)
        if not upload.done:
            chunk_dir = _chunk_dir(checksum)
            os.makedirs(chunk_dir, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='part-', dir=chunk_dir) as work_dir:
                source = os.path.join(work_dir, 'part')
                part.save(source)
                upload.update(pull__finished_parts=idx)
                os.replace(source, os.path.join(chunk_dir, str(idx)))
    return 'OK'

@app.route('/api/1/multiupload/verify_part', methods={'POST'})
def verify_chunk():
    user = verify_token()
    if not user:
        abort(403)

    checksum = _upload_id()
    with _upload_lock(checksum):
        upload = _get_upload(checksum)
        idx = _part_index(upload)
        if upload.done:
            return jsonify(result=True)
        chunk_path = os.path.join(_chunk_dir(checksum), str(idx))
        try:
            with open(chunk_path, 'rb') as chunk:
                if gen_hash(chunk, 'sha256', read_size=1024 * 1024) != request.form['checksum']:
                    return jsonify(result=False, reason='checksum')
        except FileNotFoundError:
            return jsonify(result=False, reason='part missing')
        upload.update(add_to_set__finished_parts=idx)
    return jsonify(result=True)


def _part_index(upload):
    idx = request.form.get('part', type=int)
    if idx is None or not 0 <= idx < upload.total_parts:
        abort(400)
    return idx

