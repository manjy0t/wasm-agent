"""Local client files: POSIX permissions or Windows owner/DACL checks.

Windows secrets are created with a protected DACL, before any bytes are written.
Readers check the opened handle, including reparse-point and ACL information.
The Linux VM code continues to use the original owner/mode checks.
"""
import os
from pathlib import Path, PureWindowsPath
import secrets
import stat
import tempfile


def _windows_api():
    try:
        import msvcrt
        import ntsecuritycon
        import win32api
        import win32con
        import win32file
        import win32security
    except ImportError as exc:
        raise ValueError('Windows client needs pywin32; install requirements-signing.txt with your Windows Python.') from exc
    return msvcrt, ntsecuritycon, win32api, win32con, win32file, win32security


def _windows_identity(api):
    _, _, win32api, win32con, _, security = api
    token = security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        user = security.GetTokenInformation(token, security.TokenUser)[0]
    finally:
        token.Close()
    # Administrators and SYSTEM are the local OS trust boundary, like root on Unix.
    trusted = {security.ConvertSidToStringSid(user), 'S-1-5-18', 'S-1-5-32-544'}
    return user, trusted


def _windows_check(handle, path, private, api):
    _, _, _, con, files, security = api
    attributes = files.GetFileInformationByHandle(handle)[0]
    if (files.GetFileType(handle) != files.FILE_TYPE_DISK
            or attributes & (con.FILE_ATTRIBUTE_DIRECTORY | con.FILE_ATTRIBUTE_REPARSE_POINT)):
        raise ValueError('Expected a regular file, not a link/reparse point: ' + str(path))
    if not private:
        return
    user, trusted = _windows_identity(api)
    sd = security.GetSecurityInfo(handle, security.SE_FILE_OBJECT,
                                 security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION)
    if sd.GetSecurityDescriptorOwner() != user:
        raise ValueError('Private file must be owned by the current Windows user: ' + str(path))
    acl = sd.GetSecurityDescriptorDacl()
    if acl is None:
        raise ValueError('Private file has an unrestricted Windows ACL: ' + str(path))
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        kind, flags = ace[0]
        if flags & con.INHERIT_ONLY_ACE:
            continue
        if kind == security.ACCESS_DENIED_ACE_TYPE:
            continue
        if kind != security.ACCESS_ALLOWED_ACE_TYPE or security.ConvertSidToStringSid(ace[-1]) not in trusted:
            raise ValueError('Private file grants access outside your Windows account, SYSTEM and Administrators: '
                             + str(path) + '. Restrict it in Properties > Security before retrying.')


def _windows_open(path, create=False, private=True):
    api = _windows_api()
    msvcrt, rights, _, con, files, security = api
    attributes = None
    if create:
        user, trusted = _windows_identity(api)
        acl = security.ACL()
        for sid in sorted(trusted):
            acl.AddAccessAllowedAce(security.ACL_REVISION, rights.FILE_ALL_ACCESS,
                                    security.ConvertStringSidToSid(sid))
        descriptor = security.SECURITY_DESCRIPTOR()
        descriptor.SetSecurityDescriptorOwner(user, False)
        descriptor.SetSecurityDescriptorDacl(True, acl, False)
        descriptor.SetSecurityDescriptorControl(security.SE_DACL_PROTECTED, security.SE_DACL_PROTECTED)
        attributes = security.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = descriptor
        attributes.bInheritHandle = False
    try:
        handle = files.CreateFile(str(path), con.GENERIC_READ | (con.GENERIC_WRITE if create else 0),
                                  con.FILE_SHARE_READ | con.FILE_SHARE_DELETE, attributes,
                                  con.CREATE_NEW if create else con.OPEN_EXISTING,
                                  files.FILE_FLAG_OPEN_REPARSE_POINT, None)
    except Exception as exc:
        code = getattr(exc, 'winerror', None)
        if code is None:
            raise  # Do not disguise a programming error as a file-access failure.
        error = FileExistsError if code in (80, 183) else FileNotFoundError if code in (2, 3) else PermissionError if code == 5 else OSError
        raise error('Cannot open local file ' + str(path) + ': ' + str(exc)) from exc
    try:
        _windows_check(handle, path, private, api)
        # Transfer ownership to the CRT fd; fdopen/os.close closes the OS handle.
        fd = msvcrt.open_osfhandle(int(handle), os.O_BINARY | (os.O_RDWR if create else os.O_RDONLY))
        handle.Detach()
        handle = None
        return fd
    finally:
        if handle is not None:
            handle.Close()


def create_private(path):
    if os.name == 'nt':
        return _windows_open(path, create=True)
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)


def read_regular(path, private=False, maximum=2 * 1024 * 1024):
    fd = _windows_open(path, private=private) if os.name == 'nt' else os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Expected a regular file: ' + str(path))
        if private and os.name != 'nt':
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError('Private file must be owned by this user and have mode 600: ' + str(path))
        data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError('File exceeds size limit: ' + str(path))
        return data


def write_private(path, data, exclusive=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if exclusive:
        fd, temporary = create_private(path), None
    elif os.name == 'nt':
        temporary = path.parent / ('.write-' + secrets.token_hex(16))
        fd = create_private(temporary)
    else:
        fd, temporary = tempfile.mkstemp(prefix='.write-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if temporary is not None:
            os.replace(temporary, path)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


def resolve_ca_file(config_path, value):
    """Resolve new relative CA paths and a moved deployment's existing ca.pem.

    Only look beside the config or in its fleet-tls directory. The issuer key
    stays pinned and TLS verification stays enabled; no network trust discovery.
    """
    if not value:
        return None
    parent = Path(config_path).resolve().parent
    given = Path(value).expanduser()
    candidates = [given] if given.is_absolute() else [parent / given, given]
    # Old deployment/client JSON contains an absolute path from the old machine.
    if given.name == 'ca.pem' or PureWindowsPath(value).name == 'ca.pem':
        candidates += [parent / 'ca.pem', parent / 'fleet-tls' / 'ca.pem']
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())
    raise ValueError('CA certificate not found. Keep the trusted ca.pem beside deployment.json '
                     '(normally state/fleet-tls/ca.pem), or pass --ca-file when onboarding.')
