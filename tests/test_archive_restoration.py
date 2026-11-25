import os
import unittest

from common import (Base, UPLOADS, client, create_mod, finish, make_user, models, release,
                    send_chunks, sha, upload_chunked, upload_small)


class ArchiveRestoration(Base):
    data = b'fixture archive'

    def setUp(self):
        super().setUp()
        self.editor = make_user('editor')
        self.reader = make_user('reader')
        self.checksum = sha(self.data)
        create_mod(self.editor, 'original')

    def record(self):
        return models.UploadedFile.objects.get(checksum=self.checksum)

    def start(self, user):
        return client.post('/api/1/multiupload/start', headers=user,
                           data={'id': self.checksum, 'size': len(self.data), 'parts': 1})

    def test_only_editors_can_restore_a_missing_archive(self):
        self.assertTrue(upload_chunked(self.editor, self.checksum, self.data, self.checksum).get_json()['result'])
        self.assertTrue(release(self.editor, 'original', '1.0.0', self.checksum).get_json()['result'])
        record = self.record()
        self.assertEqual(record.mod.mid, 'original')
        record.mod.update(push__team=models.TeamMember(user=models.User.objects.get(username='reader'),
                                                       role=models.TEAM_TESTER))
        path = os.path.join(UPLOADS, record.filename)
        os.unlink(path)

        self.assertEqual(self.start(self.reader).status_code, 403)
        self.assertTrue(models.ChunkedUpload.objects.get(id=self.checksum).done)
        self.assertEqual(upload_small(self.reader, self.data).status_code, 403)
        send_chunks(self.reader, '1234', self.data)
        self.assertEqual(finish(self.reader, '1234', self.checksum).status_code, 403)
        self.assertFalse(os.path.exists(path))
        self.assertTrue(upload_small(self.editor, self.data).get_json()['result'])
        os.unlink(path)
        self.assertTrue(upload_chunked(self.editor, self.checksum, self.data, self.checksum).get_json()['result'])
        with open(path, 'rb') as stream:
            self.assertEqual(stream.read(), self.data)

    def test_new_release_cannot_claim_an_older_archives_missing_ownership(self):
        self.assertTrue(upload_small(self.editor, self.data).get_json()['result'])
        self.assertTrue(release(self.editor, 'original', '1.0.0', self.checksum).get_json()['result'])
        models.UploadedFile._get_collection().update_one({'_id': self.checksum}, {'$unset': {'mod': ''}})
        create_mod(self.reader, 'second')
        self.assertTrue(release(self.reader, 'second', '1.0.0', self.checksum).get_json()['result'])
        self.assertIsNone(self.record().mod)
        path = os.path.join(UPLOADS, self.record().filename)
        os.unlink(path)
        self.assertEqual(upload_small(self.reader, self.data).status_code, 403)
        self.assertEqual(upload_small(self.editor, self.data).status_code, 403)
        self.assertFalse(os.path.exists(path))

    def test_cold_mirror_remains_authoritative_with_missing_or_stale_size(self):
        self.assertTrue(upload_small(self.editor, self.data).get_json()['result'])
        self.assertTrue(release(self.editor, 'original', '1.0.0', self.checksum).get_json()['result'])
        record = self.record()
        path = os.path.join(UPLOADS, record.filename)
        os.unlink(path)
        for size, session in ((None, 'a1'), (len(self.data) + 20, 'a2')):
            with self.subTest(size=size):
                record.update(set__storage='cold', set__filesize=size)
                self.assertTrue(self.start(self.editor).get_json()['done'])
                self.assertTrue(upload_chunked(self.editor, session, self.data, self.checksum).get_json()['result'])
                self.assertTrue(upload_small(self.editor, self.data).get_json()['result'])
                self.assertEqual(self.record().storage, 'cold')
                self.assertEqual(self.record().filesize, size)
                self.assertFalse(os.path.exists(path))

    def test_mixed_release_only_claims_the_new_archive(self):
        self.assertTrue(upload_chunked(self.editor, 'a1', self.data, self.checksum).get_json()['result'])
        self.assertTrue(release(self.editor, 'original', '1.0.0', self.checksum).get_json()['result'])
        models.UploadedFile._get_collection().update_one({'_id': self.checksum}, {'$unset': {'mod': ''}})
        new_data = b'second archive'
        new_checksum = sha(new_data)
        self.assertTrue(upload_chunked(self.reader, 'a2', new_data, new_checksum).get_json()['result'])
        create_mod(self.reader, 'second')
        files = [{'filename': checksum + '.7z', 'dest': '', 'filesize': size, 'checksum': ['sha256', checksum]}
                 for checksum, size in ((self.checksum, len(self.data)), (new_checksum, len(new_data)))]
        response = client.post('/api/1/mod/release', headers=self.reader, json={
            'id': 'second', 'version': '1.0.0', 'mod_flag': [],
            'packages': [{'name': 'core', 'files': files, 'filelist': []}]})
        self.assertTrue(response.get_json()['result'])
        self.assertIsNone(self.record().mod)
        self.assertEqual(models.UploadedFile.objects.get(checksum=new_checksum).mod.pk, 'second')


if __name__ == '__main__':
    unittest.main()
