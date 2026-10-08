"""Private local files and durable publication on POSIX and Windows.

Windows uses protected current-user DACLs, checked on the open object rather
than synthetic POSIX mode bits. No credentials or file contents are logged.
"""
from __future__ import annotations
import os
from pathlib import Path
import stat
import tempfile
import uuid

WINDOWS = os.name == "nt"

if WINDOWS:
    import ctypes as c
    from ctypes import wintypes as w
    import msvcrt

    kernel = c.WinDLL("kernel32", use_last_error=True)
    advapi = c.WinDLL("advapi32", use_last_error=True)
    native = c.WinDLL("ntdll")
    PTR = c.c_void_p
    INVALID = PTR(-1).value

    class SECURITY_ATTRIBUTES(c.Structure):
        _fields_ = [("length", w.DWORD), ("descriptor", PTR), ("inherit", w.BOOL)]

    class ACL(c.Structure):
        _fields_ = [("revision", w.BYTE), ("reserved", w.BYTE),
                    ("size", w.WORD), ("count", w.WORD), ("reserved2", w.WORD)]

    class ACE(c.Structure):
        _fields_ = [("kind", w.BYTE), ("flags", w.BYTE), ("size", w.WORD),
                    ("mask", w.DWORD), ("sid", w.DWORD)]

    class FILE_INFO(c.Structure):
        _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME),
                    ("accessed", w.FILETIME), ("written", w.FILETIME),
                    ("volume", w.DWORD), ("sizeHigh", w.DWORD),
                    ("sizeLow", w.DWORD), ("links", w.DWORD),
                    ("indexHigh", w.DWORD), ("indexLow", w.DWORD)]

    class OVERLAPPED(c.Structure):
        _fields_ = [("internal", c.c_size_t), ("internalHigh", c.c_size_t),
                    ("offset", w.DWORD), ("offsetHigh", w.DWORD), ("event", w.HANDLE)]

    class UNICODE_STRING(c.Structure):
        _fields_ = [("length", w.WORD), ("maximumLength", w.WORD), ("buffer", w.LPWSTR)]

    class OBJECT_ATTRIBUTES(c.Structure):
        _fields_ = [("length", w.ULONG), ("root", w.HANDLE),
                    ("name", c.POINTER(UNICODE_STRING)), ("attributes", w.ULONG),
                    ("descriptor", PTR), ("qualityOfService", PTR)]

    class IO_STATUS_BLOCK(c.Structure):
        _fields_ = [("status", PTR), ("information", c.c_size_t)]

    def _bind(dll, name, args, result):
        function = getattr(dll, name)
        function.argtypes, function.restype = args, result
        return function

    _bind(kernel, "GetCurrentProcess", [], w.HANDLE)
    _bind(kernel, "CloseHandle", [w.HANDLE], w.BOOL)
    _bind(kernel, "LocalFree", [PTR], PTR)
    _bind(kernel, "CreateFileW", [w.LPCWSTR, w.DWORD, w.DWORD, PTR, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE)
    _bind(kernel, "CreateDirectoryW", [w.LPCWSTR, PTR], w.BOOL)
    _bind(kernel, "GetFileInformationByHandle", [w.HANDLE, c.POINTER(FILE_INFO)], w.BOOL)
    _bind(kernel, "LockFileEx", [w.HANDLE, w.DWORD, w.DWORD, w.DWORD, w.DWORD, c.POINTER(OVERLAPPED)], w.BOOL)
    _bind(kernel, "MoveFileExW", [w.LPCWSTR, w.LPCWSTR, w.DWORD], w.BOOL)
    _bind(advapi, "OpenProcessToken", [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)], w.BOOL)
    _bind(advapi, "GetTokenInformation", [w.HANDLE, c.c_int, PTR, w.DWORD, c.POINTER(w.DWORD)], w.BOOL)
    _bind(advapi, "ConvertSidToStringSidW", [PTR, c.POINTER(PTR)], w.BOOL)
    _bind(advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [w.LPCWSTR, w.DWORD, c.POINTER(PTR), PTR], w.BOOL)
    _bind(advapi, "GetSecurityInfo", [w.HANDLE, c.c_int, w.DWORD, c.POINTER(PTR), PTR, c.POINTER(PTR), PTR, c.POINTER(PTR)], w.DWORD)
    _bind(advapi, "GetSecurityDescriptorControl", [PTR, c.POINTER(w.WORD), c.POINTER(w.DWORD)], w.BOOL)
    _bind(advapi, "GetSecurityDescriptorOwner", [PTR, c.POINTER(PTR), c.POINTER(w.BOOL)], w.BOOL)
    _bind(advapi, "GetSecurityDescriptorDacl", [PTR, c.POINTER(w.BOOL), c.POINTER(PTR), c.POINTER(w.BOOL)], w.BOOL)
    _bind(advapi, "SetSecurityInfo", [w.HANDLE, c.c_int, w.DWORD, PTR, PTR, PTR, PTR], w.DWORD)
    _bind(advapi, "GetAce", [PTR, w.DWORD, c.POINTER(PTR)], w.BOOL)
    _bind(advapi, "EqualSid", [PTR, PTR], w.BOOL)
    _bind(native, "NtOpenFile", [c.POINTER(w.HANDLE), w.ULONG, c.POINTER(OBJECT_ATTRIBUTES),
                                c.POINTER(IO_STATUS_BLOCK), w.ULONG, w.ULONG], w.LONG)
    _bind(native, "RtlNtStatusToDosError", [w.LONG], w.ULONG)

    def _check(ok):
        if not ok:
            raise c.WinError(c.get_last_error())

    def _current_user():
        token, needed = w.HANDLE(), w.DWORD()
        _check(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(token)))
        try:
            advapi.GetTokenInformation(token, 1, None, 0, c.byref(needed))
            storage = c.create_string_buffer(needed.value)
            _check(advapi.GetTokenInformation(token, 1, storage, needed, c.byref(needed)))
            return storage, c.cast(storage, c.POINTER(PTR))[0]
        finally:
            kernel.CloseHandle(token)

    def _descriptor(directory=False):
        storage, sid = _current_user()
        text, descriptor = PTR(), PTR()
        _check(advapi.ConvertSidToStringSidW(sid, c.byref(text)))
        try:
            sid_text = c.wstring_at(text)
            _check(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                "O:" + sid_text + "D:P(A;" + ("OICI" if directory else "") + ";FA;;;" + sid_text + ")",
                1, c.byref(descriptor), None))
            return descriptor
        finally:
            kernel.LocalFree(text)

    def _open(path, access=0x80020000, creation=3, security=None, directory=False):
        # OPEN_REPARSE_POINT pins the final object and lets validation reject it.
        handle = kernel.CreateFileW(str(Path(path).absolute()), access, 7, security,
                                    creation, 0x00200000 | (0x02000000 if directory else 0), None)
        if handle == INVALID:
            raise c.WinError(c.get_last_error())
        return handle

    def _open_security(path, directory=False):
        # NtOpenFile avoids CreateFileW's implicit I/O rights. An existing
        # owner may only have READ_CONTROL/WRITE_DAC when a copy inherited an
        # empty DACL. READ_ATTRIBUTES is used to reject reparses and links.
        # No WRITE_OWNER, data access, synchronization, or privilege override.
        full = str(Path(path).absolute())
        if full.startswith("\\\\.\\") or "\x00" in full:
            raise OSError("invalid private filesystem path")
        if full.startswith("\\\\?\\"):
            full = full[4:]
        native_path = "\\??\\" + ("UNC\\" + full[2:] if full.startswith("\\\\") else full)
        length = len(native_path.encode("utf-16-le"))
        if length > 65532:
            raise OSError("private filesystem path is too long")
        name = UNICODE_STRING(length, length + 2, native_path)
        attributes = OBJECT_ATTRIBUTES(c.sizeof(OBJECT_ATTRIBUTES), None, c.pointer(name), 0x40, None, None)
        handle, status = w.HANDLE(), IO_STATUS_BLOCK()
        result = native.NtOpenFile(c.byref(handle), 0x00060080, c.byref(attributes), c.byref(status),
                                   7, 0x00200000 | (1 if directory else 0x40))
        if result < 0:
            raise c.WinError(native.RtlNtStatusToDosError(result))
        return handle

    def _validate_handle(handle, directory=False):
        info = FILE_INFO()
        _check(kernel.GetFileInformationByHandle(handle, c.byref(info)))
        if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory or (not directory and info.links != 1):
            raise OSError("private path must be a regular, unlinked object")
        owner, dacl, sd = PTR(), PTR(), PTR()
        result = advapi.GetSecurityInfo(handle, 1, 5, c.byref(owner), None, c.byref(dacl), None, c.byref(sd))
        if result:
            raise c.WinError(result)
        try:
            control, revision = w.WORD(), w.DWORD()
            _check(advapi.GetSecurityDescriptorControl(sd, c.byref(control), c.byref(revision)))
            storage, user = _current_user()
            if not control.value & 0x1000 or not control.value & 4 or not owner or not advapi.EqualSid(owner, user) or not dacl:
                raise OSError("private path requires a protected current-user DACL")
            acl = c.cast(dacl, c.POINTER(ACL)).contents
            grants_control = False
            for index in range(acl.count):
                pointer = PTR()
                _check(advapi.GetAce(dacl, index, c.byref(pointer)))
                ace = c.cast(pointer, c.POINTER(ACE)).contents
                if ace.kind != 0 or ace.flags & 0x10 or not advapi.EqualSid(pointer.value + ACE.sid.offset, user):
                    raise OSError("private path grants another principal or inherits permissions")
                required = 0x001F01FF
                if not ace.flags & 8 and (ace.mask & 0x10000000 or ace.mask & required == required):
                    grants_control = True
            if not grants_control:
                raise OSError("private path must grant current-user control")
        finally:
            kernel.LocalFree(sd)


def protect(path, directory=False):
    """Protect a newly created, caller-owned path before writing private data."""
    if not WINDOWS:
        os.chmod(path, 0o700 if directory else 0o600)
        return
    descriptor, handle = _descriptor(directory=directory), None
    try:
        handle = _open_security(path, directory=directory)
        info = FILE_INFO()
        _check(kernel.GetFileInformationByHandle(handle, c.byref(info)))
        if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory or (not directory and info.links != 1):
            raise OSError("cannot protect a linked or unexpected object")
        previous_owner, previous_sd = PTR(), PTR()
        result = advapi.GetSecurityInfo(handle, 1, 1, c.byref(previous_owner), None, None, None, c.byref(previous_sd))
        if result:
            raise c.WinError(result)
        try:
            storage, current_user = _current_user()
            if not previous_owner or not advapi.EqualSid(previous_owner, current_user):
                raise OSError("cannot change permissions on another user's object")
        finally:
            kernel.LocalFree(previous_sd)
        dacl, defaulted, present = PTR(), w.BOOL(), w.BOOL()
        _check(advapi.GetSecurityDescriptorDacl(descriptor, c.byref(present), c.byref(dacl), c.byref(defaulted)))
        result = advapi.SetSecurityInfo(handle, 1, 0x80000004, None, None, dacl, None)
        if result:
            raise c.WinError(result)
        _validate_handle(handle, directory)
    finally:
        if handle is not None:
            kernel.CloseHandle(handle)
        kernel.LocalFree(descriptor)


def validate(path, directory=False, descriptor=None):
    if not WINDOWS:
        info = os.fstat(descriptor) if descriptor is not None else Path(path).lstat()
        expected = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected(info.st_mode) or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600) or info.st_uid != os.getuid():
            raise OSError("private path permissions are invalid")
        return
    if descriptor is not None:
        _validate_handle(msvcrt.get_osfhandle(descriptor), directory)
        return
    handle = _open(path, access=0x20000, directory=directory)
    try:
        _validate_handle(handle, directory)
    finally:
        kernel.CloseHandle(handle)


def open_read(path):
    if not WINDOWS:
        return os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    handle = _open(path)
    try:
        _validate_handle(handle)
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = None
        return descriptor
    finally:
        if handle is not None:
            kernel.CloseHandle(handle)


def create_file(path, existing=False):
    if not WINDOWS:
        return os.open(path, os.O_RDWR | os.O_CREAT | (0 if existing else os.O_EXCL) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    sd = _descriptor()
    handle = None
    try:
        attributes = SECURITY_ATTRIBUTES(c.sizeof(SECURITY_ATTRIBUTES), sd, False)
        handle = _open(path, access=0xC0020000, creation=4 if existing else 1, security=c.byref(attributes))
        _validate_handle(handle)
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        handle = None
        return descriptor
    finally:
        if handle is not None:
            kernel.CloseHandle(handle)
        kernel.LocalFree(sd)


def private_tempdir(prefix, directory=None):
    if not WINDOWS:
        return Path(tempfile.mkdtemp(prefix=prefix, **({"dir": directory} if directory is not None else {})))
    sd = _descriptor()
    try:
        attributes = SECURITY_ATTRIBUTES(c.sizeof(SECURITY_ATTRIBUTES), sd, False)
        for _ in range(20):
            path = Path(directory if directory is not None else tempfile.gettempdir()) / (prefix + uuid.uuid4().hex)
            if kernel.CreateDirectoryW(str(path), c.byref(attributes)):
                validate(path, directory=True)
                return path
            if c.get_last_error() != 183:
                raise c.WinError(c.get_last_error())
        raise FileExistsError("private temporary directory collision")
    finally:
        kernel.LocalFree(sd)


def private_tempfile(prefix, directory):
    if not WINDOWS:
        return tempfile.mkstemp(prefix=prefix, dir=directory)
    for _ in range(20):
        path = Path(directory) / (prefix + uuid.uuid4().hex)
        try:
            return create_file(path), str(path)
        except FileExistsError:
            continue
    raise FileExistsError("private temporary file collision")


def protect_descriptor(descriptor, path=None):
    if WINDOWS:
        validate(path, descriptor=descriptor)
    else:
        os.fchmod(descriptor, 0o600)


def lock_exclusive(descriptor):
    if WINDOWS:
        overlap = OVERLAPPED()
        # Locks remain held until the descriptor closes, including process exit.
        _check(kernel.LockFileEx(msvcrt.get_osfhandle(descriptor), 3, 0, 1, 0, c.byref(overlap)))
    else:
        import fcntl
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def replace_durable(source, target):
    if WINDOWS:
        # Same-volume atomic replacement plus MOVEFILE_WRITE_THROUGH. Source
        # bytes must already be fsynced; no copy fallback is admitted.
        _check(kernel.MoveFileExW(str(source), str(target), 1 | 8))
    else:
        os.replace(source, target)


def publish_exclusive(source, target):
    # On POSIX the caller must record ownership of target before unlinking
    # source, so a failed unlink cannot leave an untracked published file.
    if WINDOWS:
        _check(kernel.MoveFileExW(str(source), str(target), 8))
    else:
        os.link(source, target, follow_symlinks=False)


def sync_directory(path, private=False):
    if WINDOWS:
        # Windows does not support POSIX fsync(directory). Each publication
        # above requests write-through, after FlushFileBuffers via os.fsync.
        if private:
            validate(path, directory=True)
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        if private:
            validate(path, directory=True, descriptor=descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Protect a newly created CosmoEdge Connect request file for the current user.")
    parser.add_argument("action", choices=["protect"])
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    protect(args.path)
    validate(args.path)
