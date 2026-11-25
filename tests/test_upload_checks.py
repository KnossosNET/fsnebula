import os
import threading
from unittest import mock

from common import Base, UPLOADS, client, create_mod, make_user, models, release, sha, upload_small
from app.controllers import upload


class CheckStoredUpload(Base):
    def setUp(self):
        super().setUp()
        self.headers = make_user('editor')
        self.data = b'stored test archive'
        self.checksum = sha(self.data)

    def check(self):
        return client.post('/api/1/upload/check', headers=self.headers, data={'checksum': self.checksum})

    def legacy_record(self, permanent=True, size=None):
        record = models.UploadedFile(checksum=self.checksum, filesize=len(self.data),
                                     expires=-1 if permanent else 12345678)
        record.gen_filename()
        record.save()
        path = os.path.join(UPLOADS, record.filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as stream:
            stream.write(self.data)
        models.ChunkedUpload(id=self.checksum, filesize=size or len(self.data), total_parts=1,
                             done=permanent).save()
        return record, path

    def test_abandoned_session_does_not_hide_or_promote_a_temporary_upload(self):
        self.legacy_record(permanent=False, size=12345)
        self.assertTrue(self.check().get_json()['result'])
        self.assertNotEqual(models.UploadedFile.objects.get().expires, -1)
        create_mod(self.headers, 'release')
        self.assertTrue(release(self.headers, 'release', '1.0.0', self.checksum).get_json()['result'])
        self.assertEqual(models.UploadedFile.objects.get().expires, -1)

    def test_untracked_missing_archive_is_unavailable_for_release(self):
        record, path = self.legacy_record()
        models.ChunkedUpload.objects.delete()
        os.unlink(path)
        self.assertFalse(self.check().get_json()['result'])
        create_mod(self.headers, 'release')
        response = release(self.headers, 'release', '1.0.0', record.checksum)
        self.assertEqual(response.get_json()['reason'], 'archive missing')
        self.assertFalse(models.ModRelease.objects.count())

    def test_busy_checksum_does_not_block_check_or_release(self):
        self.legacy_record()
        create_mod(self.headers, 'release')
        with upload._checksum_lock(self.checksum):
            for response in (self.check(), release(self.headers, 'release', '1.0.0', self.checksum)):
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.headers['Retry-After'], '2')
                self.assertEqual(response.get_json()['reason'], 'archive verification pending')
        self.assertFalse(models.ModRelease.objects.count())
        self.assertTrue(self.check().get_json()['result'])

    def test_large_unverified_file_hashes_outside_the_request(self):
        self.legacy_record()
        started, resume = threading.Event(), threading.Event()
        real_hash = upload.gen_hash

        def slow_hash(*args, **kwargs):
            self.assertNotEqual(threading.current_thread(), threading.main_thread())
            started.set()
            if not resume.wait(5):
                raise AssertionError('The HTTP request waited for the background hash')
            return real_hash(*args, **kwargs)

        with mock.patch.object(upload, 'SYNC_VERIFY_BYTES', 1), mock.patch.object(upload, 'gen_hash', slow_hash):
            try:
                self.assertEqual(self.check().status_code, 503)
                self.assertTrue(started.wait(5))
                self.assertEqual(self.check().status_code, 503)
            finally:
                resume.set()
                self.assertTrue(upload._verification_slot.acquire(timeout=5))
                upload._verification_slot.release()
        with mock.patch.object(upload, 'gen_hash', side_effect=AssertionError('read twice')):
            self.assertTrue(self.check().get_json()['result'])

    def test_warmup_rejects_same_size_corruption_and_invalidates_a_negative_cache(self):
        record, path = self.legacy_record()
        with open(path, 'wb') as stream:
            stream.write(b'x' * len(self.data))
        self.assertIsNone(upload.checked_upload_record(record, warm=True))
        with mock.patch.object(upload, 'gen_hash', side_effect=AssertionError('read twice')):
            self.assertFalse(self.check().get_json()['result'])
        replacement = path + '.replacement'
        with open(replacement, 'wb') as stream:
            stream.write(self.data)
        os.replace(replacement, path)
        with mock.patch.object(upload, 'SYNC_VERIFY_BYTES', 1):
            self.assertIsNotNone(upload.checked_upload_record(record, warm=True))
            self.assertTrue(self.check().get_json()['result'])

    def test_duplicate_temporary_upload_uses_verified_fingerprint(self):
        self.assertTrue(upload_small(self.headers, self.data).get_json()['result'])
        with mock.patch.object(upload, 'gen_hash', wraps=upload.gen_hash) as digest:
            self.assertTrue(upload_small(self.headers, self.data).get_json()['result'])
            self.assertEqual(digest.call_count, 1)
