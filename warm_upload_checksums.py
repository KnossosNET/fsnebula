#!/usr/bin/env python
"""Prepare the upload checksum cache before routing traffic to an upgraded server.

Run with the app's Python environment, NEBULA_SETTINGS and storage permissions.
On-demand verification of large archives uses Python threads under uWSGI.
Running this command ahead of time lets existing clients use those archives on
their first release request. It is safe to interrupt and rerun.
"""
from app.controllers.upload import checked_upload_record
from app.models import UploadedFile


def main():
    available = unavailable = 0
    for record in UploadedFile.objects.no_cache().timeout(False):
        if checked_upload_record(record, warm=True):
            available += 1
        else:
            unavailable += 1
            print('Missing or invalid: ' + record.checksum)
    print('Available: %d, missing or invalid: %d' % (available, unavailable))


if __name__ == '__main__':
    main()
