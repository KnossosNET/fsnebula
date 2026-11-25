import io
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from werkzeug.datastructures import FileStorage

from common import Base, app, finish, make_user, models, sha
from app.controllers import upload


class ConcurrentParts(Base):
    upload_id = 'c0ffee'

    def setUp(self):
        super().setUp()
        self.headers = make_user('parts')
        response = self.post('start', size=2, parts=2)
        self.assertEqual(response.status_code, 200)

    def post(self, endpoint, **data):
        data['id'] = self.upload_id
        return app.test_client().post('/api/1/multiupload/' + endpoint, headers=self.headers, data=data)

    def put(self, index, data):
        return self.post('part', part=index, file=(io.BytesIO(data), str(index)))

    def verify(self, index, data):
        return self.post('verify_part', part=index, checksum=sha(data))

    def test_another_part_can_be_committed_while_the_first_is_being_copied(self):
        copying, resume = threading.Event(), threading.Event()
        save = FileStorage.save

        def pause_first(part, *args, **kwargs):
            if part.filename == '0':
                copying.set()
                self.assertTrue(resume.wait(timeout=10))
            return save(part, *args, **kwargs)

        with patch.object(FileStorage, 'save', pause_first), ThreadPoolExecutor(2) as workers:
            first = workers.submit(self.put, 0, b'a')
            try:
                self.assertTrue(copying.wait(timeout=5))
                self.assertEqual(workers.submit(self.put, 1, b'b').result(timeout=3).data, b'OK')
                self.assertTrue(self.verify(1, b'b').get_json()['result'])
                self.assertEqual(finish(self.headers, self.upload_id, sha(b'ab')).status_code, 503)
            finally:
                resume.set()
            self.assertEqual(first.result(timeout=3).data, b'OK')
        self.assertTrue(finish(self.headers, self.upload_id, sha(b'ab')).get_json()['result'])

    def test_verification_can_overlap_another_index_and_cannot_certify_replaced_bytes(self):
        self.assertEqual(self.put(0, b'a').data, b'OK')
        self.assertEqual(self.put(1, b'b').data, b'OK')
        verifying, resume = threading.Event(), threading.Event()
        gen_hash = upload.gen_hash

        def pause_first(stream, *args, **kwargs):
            if stream.name.endswith('0'):
                verifying.set()
                self.assertTrue(resume.wait(timeout=10))
            return gen_hash(stream, *args, **kwargs)

        with patch.object(upload, 'gen_hash', pause_first), ThreadPoolExecutor(2) as workers:
            first = workers.submit(self.verify, 0, b'a')
            try:
                self.assertTrue(verifying.wait(timeout=5))
                self.assertTrue(workers.submit(self.verify, 1, b'b').result(timeout=3).get_json()['result'])
                self.assertEqual(workers.submit(self.put, 0, b'x').result(timeout=3).status_code, 503)
            finally:
                resume.set()
            self.assertTrue(first.result(timeout=3).get_json()['result'])
        self.assertEqual(self.put(0, b'x').data, b'OK')
        self.assertEqual(models.ChunkedUpload.objects.get(id=self.upload_id).finished_parts, [1])
        self.assertFalse(self.verify(0, b'a').get_json()['result'])
        self.assertTrue(self.verify(0, b'x').get_json()['result'])

    def test_upload_and_verify_return_busy_while_finish_owns_the_session(self):
        with ThreadPoolExecutor(2) as workers:
            with upload._upload_lock(self.upload_id):
                for task in (workers.submit(self.put, 0, b'a'), workers.submit(self.verify, 1, b'b')):
                    response = task.result(timeout=3)
                    self.assertEqual(response.status_code, 503)
                    self.assertEqual(response.headers['Retry-After'], '2')
        self.assertEqual(self.put(0, b'a').data, b'OK')
        self.assertTrue(self.verify(0, b'a').get_json()['result'])


if __name__ == '__main__':
    unittest.main()
