import os
from contextlib import contextmanager


if os.name == 'nt':
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _Overlapped(ctypes.Structure):
        _fields_ = [('Internal', ctypes.c_size_t), ('InternalHigh', ctypes.c_size_t),
                    ('Offset', wintypes.DWORD), ('OffsetHigh', wintypes.DWORD),
                    ('hEvent', wintypes.HANDLE)]

    _kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    _exclusive_lock = 2
    _fail_immediately = 1
    _lock_violation = 33

    @contextmanager
    def _lock_file(stream, wait, shared):
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(stream.fileno()))
        region = ctypes.byref(_Overlapped())
        flags = 0 if shared else _exclusive_lock
        if not wait:
            flags |= _fail_immediately
        if not _kernel.LockFileEx(handle, flags, 0, 1, 0, region):
            error = ctypes.get_last_error()
            if wait or error != _lock_violation:
                raise ctypes.WinError(error)
            yield None
            return
        try:
            yield stream
        finally:
            if not _kernel.UnlockFileEx(handle, 0, 1, 0, region):
                raise ctypes.WinError(ctypes.get_last_error())

else:
    from fcntl import flock, LOCK_EX, LOCK_NB, LOCK_SH

    @contextmanager
    def _lock_file(stream, wait, shared):
        mode = LOCK_SH if shared else LOCK_EX
        try:
            flock(stream, mode if wait else mode | LOCK_NB)
        except BlockingIOError:
            yield None
        else:
            yield stream


@contextmanager
def storage_lock(path, wait=True, shared=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a+b') as stream:
        with _lock_file(stream, wait, shared) as acquired:
            yield acquired
