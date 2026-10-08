#!/usr/bin/env python3
"""Transactional, per-user macOS paired installation. Only Python stdlib at runtime."""
import argparse
from contextlib import contextmanager, ExitStack
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import re
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import time
import urllib.request

LABEL = 'com.cosmoedge.connect'
LABELS = (LABEL,)
APP_PAYLOAD = 'payload/app'
APP_SERVICE = APP_PAYLOAD + '/Contents/MacOS/cosmoedge-connect'
APP_NAME = 'CosmoEdge Connect.app'
CLIENT = 'payload/skill/scripts/cosmoedge_operations.py'
SKILL = 'payload/skill/SKILL.md'
PLUGIN_PAYLOAD = 'payload/workbuddy-plugin'
PLUGIN_NAME = 'cosmoedge-summary-report-guard'
PLUGIN_PATH = PLUGIN_PAYLOAD + '/plugins/' + PLUGIN_NAME


class InstallError(Exception):
    pass


def sha256(path):
    with path.open('rb') as stream:
        value = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def write_private(path, data):
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(6))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_json(path, data):
    write_private(path, (json.dumps(data, indent=2, ensure_ascii=False) + '\n').encode())


def safe_tree(path, uid=None):
    """Do not follow links or special files in either payloads or backup material."""
    if path.is_symlink():
        raise InstallError('Symbolic links are not accepted in installation material.')
    info = path.lstat()
    if uid is not None and info.st_uid != uid:
        raise InstallError('Installation material belongs to another user.')
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise InstallError('Installation material contains a non-regular file.')
    if path.is_dir():
        for child in path.iterdir():
            safe_tree(child, uid)


def service_path(manifest):
    """Accept only this product's signed app layout."""
    service = manifest.get('service', {})
    app = service.get('macOSApp')
    if not isinstance(app, dict) or service.get('executablePath') != APP_SERVICE or app.get('payloadPath') != APP_PAYLOAD:
        raise InstallError('Unsupported macOS app layout.')
    signing = app.get('signing')
    expected_id = {'development-adhoc': 'com.cosmoedge.connect.development', 'apple': 'com.cosmoedge.connect'}.get(signing)
    if not expected_id or app.get('bundleIdentifier') != expected_id:
        raise InstallError('Unsupported macOS app signing identity.')
    team = app.get('teamIdentifier')
    if (signing == 'development-adhoc' and team is not None) or (signing == 'apple' and not re.fullmatch(r'[A-Z0-9]{10}', team or '')):
        raise InstallError('Invalid macOS app signing team.')
    if (not re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}', app.get('buildUUID', ''))
            or set(app['buildUUID'].replace('-', '')) == {'0'}):
        raise InstallError('The macOS app build UUID is missing.')
    return APP_SERVICE


def safe_app_tree(path, uid):
    safe_tree(path, uid)
    if not path.is_dir():
        raise InstallError('The managed CosmoEdge Connect app path is occupied by a non-directory.')
    if any(p.is_file() and p.stat().st_nlink != 1 for p in path.rglob('*')):
        raise InstallError('App material cannot contain hard links.')


def verify_app_info(app_path, app):
    info = plistlib.loads((app_path / 'Contents/Info.plist').read_bytes())
    if (not isinstance(info, dict) or info.get('CFBundleIdentifier') != app['bundleIdentifier']
            or info.get('CFBundleExecutable') != 'cosmoedge-connect' or info.get('CFBundlePackageType') != 'APPL'
            or info.get('LSUIElement') is not True
            or not isinstance(info.get('NSLocalNetworkUsageDescription'), str)
            or not info['NSLocalNetworkUsageDescription'].strip()):
        raise InstallError('App Info.plist does not describe the paired CosmoEdge Connect identity and local network use.')


def mach_o_uuid(path):
    """Read LC_UUID directly, without requiring developer tools at installation."""
    with path.open('rb') as stream:
        header = stream.read(32)
        if len(header) != 32 or header[:4] not in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf'):
            raise InstallError('App service is not a supported thin Mach-O executable.')
        endian = '<' if header[:4] == b'\xcf\xfa\xed\xfe' else '>'
        commands, size = struct.unpack_from(endian + 'II', header, 16)
        if commands > 4096 or size > 4 * 1024 * 1024:
            raise InstallError('App executable load commands are invalid.')
        data = stream.read(size)
    offset, found = 0, []
    for _ in range(commands):
        if offset + 8 > len(data):
            raise InstallError('App executable load commands are truncated.')
        kind, length = struct.unpack_from(endian + 'II', data, offset)
        if length < 8 or offset + length > len(data):
            raise InstallError('App executable load command length is invalid.')
        if kind == 0x1b:
            if length != 24:
                raise InstallError('App executable UUID command is invalid.')
            import uuid
            found.append(str(uuid.UUID(bytes=data[offset + 8:offset + 24])).upper())
        offset += length
    if len(found) != 1 or offset != size:
        raise InstallError('App executable must have exactly one build UUID.')
    return found[0]


def register_launch_services(app_path):
    """Explicit installer action via Apple's public API; never launches the app."""
    import ctypes
    core = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    services = ctypes.CDLL('/System/Library/Frameworks/CoreServices.framework/CoreServices')
    core.CFURLCreateFromFileSystemRepresentation.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_long, ctypes.c_ubyte]
    core.CFURLCreateFromFileSystemRepresentation.restype = ctypes.c_void_p
    core.CFRelease.argtypes = [ctypes.c_void_p]
    core.CFRelease.restype = None
    services.LSRegisterURL.argtypes = [ctypes.c_void_p, ctypes.c_ubyte]
    services.LSRegisterURL.restype = ctypes.c_int32
    encoded = os.fsencode(app_path)
    url = core.CFURLCreateFromFileSystemRepresentation(None, encoded, len(encoded), True)
    if not url:
        raise InstallError('Cannot form the CosmoEdge Connect app registration URL.')
    try:
        if services.LSRegisterURL(url, True) != 0:
            raise InstallError('Launch Services could not register the CosmoEdge Connect app identity.')
    finally:
        core.CFRelease(url)


def verify_bundle(bundle, expected=None):
    safe_tree(bundle)
    manifest_path = bundle / 'manifest.json'
    if expected and sha256(manifest_path) != expected:
        raise InstallError('Manifest checksum does not match the expected candidate.')
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('schemaVersion') != 1 or manifest.get('product') != 'cosmoedge-connect':
        raise InstallError('Unsupported paired manifest.')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,79}', manifest.get('version', '')):
        raise InstallError('Invalid candidate version.')
    source = manifest.get('source', {})
    if not re.fullmatch(r'[0-9a-f]{40,64}', source.get('revision', '')) or not isinstance(source.get('modified'), bool):
        raise InstallError('Manifest source identity is missing.')
    if not re.fullmatch(r'[0-9a-f]{64}', source.get('inventorySHA256', '')):
        raise InstallError('Manifest source inventory is missing.')
    if sha256(bundle / 'source-files.json') != source['inventorySHA256']:
        raise InstallError('Source inventory checksum failed.')
    if not isinstance(manifest.get('service'), dict) or manifest['service'].get('healthProtocol') != 'cosmoedge.operations.v1' or manifest['service'].get('entrypoint') != './cmd/cosmoedge-connect':
        raise InstallError('Manifest service health protocol is unsupported.')
    entries = manifest.get('files', [])
    if not isinstance(entries, list) or not entries:
        raise InstallError('Manifest has no paired files.')
    seen = set()
    roles = {}
    for entry in entries:
        name = entry.get('path', '')
        relative = PurePosixPath(name)
        if not name or relative.is_absolute() or '..' in relative.parts or str(relative) != name or name in seen:
            raise InstallError('Manifest contains an unsafe or duplicate file path.')
        seen.add(name)
        path = bundle / name
        if not path.is_file() or path.is_symlink() or sha256(path) != entry.get('sha256') or path.stat().st_size != entry.get('size'):
            raise InstallError('Paired file checksum failed: ' + name)
        roles[name] = entry.get('role')
    executable = service_path(manifest)
    if roles.get(executable) != 'service' or roles.get(CLIENT) != 'client' or roles.get(SKILL) != 'skill':
        raise InstallError('Manifest must bind service, client and Skill.')
    verify_app_info(bundle / APP_PAYLOAD, manifest['service']['macOSApp'])
    if not next(e for e in entries if e['path'] == executable).get('executable'):
        raise InstallError('The app main executable must retain execute permission.')
    actual = {p.relative_to(bundle).as_posix() for p in bundle.rglob('*') if p.is_file()}
    if actual != seen | {'manifest.json', 'source-files.json'}:
        raise InstallError('Bundle contains unlisted or missing files.')
    verify_plugin_metadata(bundle, manifest)
    mcp = manifest.get('mcp')
    if mcp is not None:
        expected_mcp = {'transport': 'stdio', 'entrypoint': './cmd/cosmoedge-mcp',
                        'executablePath': 'payload/mcp/cosmoedge-mcp', 'candidatePath': 'payload/mcp/candidate.json'}
        if mcp != expected_mcp or roles.get(mcp['executablePath']) != 'mcp' or roles.get(mcp['candidatePath']) != 'mcp-candidate':
            raise InstallError('Unsupported paired MCP layout.')
        candidate = json.loads((bundle / mcp['candidatePath']).read_text())
        identity = {'version': manifest['version'], 'revision': source['revision'],
                    'modified': source['modified'], 'platform': manifest['platform']}
        if not isinstance(candidate, dict) or any(candidate.get(key) != value for key, value in identity.items()):
            raise InstallError('MCP candidate identity differs from the paired service.')
        if not next(e for e in entries if e['path'] == mcp['executablePath']).get('executable'):
            raise InstallError('MCP executable permission is missing.')
        mode = stat.S_IMODE((bundle / mcp['executablePath']).stat().st_mode)
        if not mode & stat.S_IXUSR or mode & 0o7022:
            raise InstallError('MCP executable permissions are unsafe or cannot execute.')
    elif any(name.startswith('payload/mcp/') for name in seen):
        raise InstallError('MCP files require paired manifest metadata.')
    return manifest


def verify_plugin_metadata(bundle, manifest):
    metadata = manifest.get('workbuddyPlugin')
    entries = [e for e in manifest['files'] if e['path'].startswith(PLUGIN_PAYLOAD + '/')]
    if metadata is None and not entries:
        return None  # The report-delivery plugin is optional.
    fixed = {'schemaVersion': 1, 'name': PLUGIN_NAME, 'marketplaceName': 'cosmoedge-summary-report-guard-local',
             'sourceDirectory': 'integrations/workbuddy/plugins/summary-report-guard',
             'payloadPath': PLUGIN_PAYLOAD, 'pluginPath': PLUGIN_PATH, 'requiresNativeInstallAndEnable': True}
    if (not isinstance(metadata, dict) or set(metadata) != set(fixed) | {'version', 'sourceVersion'}
            or any(metadata.get(k) != v for k, v in fixed.items()) or not entries
            or type(metadata['schemaVersion']) is not int or metadata['requiresNativeInstallAndEnable'] is not True
            or any(e['role'] != 'workbuddy-plugin' for e in entries)
            or any(e.get('role') == 'workbuddy-plugin' and not e['path'].startswith(PLUGIN_PAYLOAD + '/') for e in manifest['files'])
            or manifest.get('platform') not in ('darwin/arm64', 'darwin/amd64')
            or not isinstance(metadata.get('sourceVersion'), str)
            or not re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', metadata['sourceVersion'])):
        raise InstallError('WorkBuddy plugin metadata is missing or unsupported.')
    candidate = {'product': 'cosmoedge-connect', 'version': manifest['version'], 'revision': manifest['source']['revision'],
                 'modified': manifest['source']['modified'], 'platform': manifest['platform']}
    identity = hashlib.sha256(json.dumps(candidate, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    version = metadata['sourceVersion'] + '-paired.c' + identity[:20]
    if metadata['version'] != version:
        raise InstallError('WorkBuddy plugin version is not bound to this candidate.')
    plugin = json.loads((bundle / PLUGIN_PATH / '.codebuddy-plugin/plugin.json').read_text())
    market = json.loads((bundle / PLUGIN_PAYLOAD / '.codebuddy-plugin/marketplace.json').read_text())
    binding = json.loads((bundle / PLUGIN_PATH / 'candidate.json').read_text())
    plugins = market.get('plugins') if isinstance(market, dict) else None
    if (not isinstance(plugin, dict) or plugin.get('name') != PLUGIN_NAME or plugin.get('version') != version
            or not isinstance(market, dict) or market.get('name') != fixed['marketplaceName']
            or not isinstance(plugins, list) or len(plugins) != 1 or not isinstance(plugins[0], dict)
            or plugins[0].get('name') != PLUGIN_NAME or plugins[0].get('source') != './plugins/' + PLUGIN_NAME
            or plugins[0].get('version') != version
            or binding != {'schemaVersion': 1, 'candidate': candidate}
            or type(binding.get('schemaVersion')) is not int or type(binding.get('candidate', {}).get('modified')) is not bool):
        raise InstallError('WorkBuddy plugin files do not describe this paired candidate.')
    expected = {e['path'] for e in entries}
    if not {PLUGIN_PATH + '/hooks/hooks.json', PLUGIN_PATH + '/scripts/post_read.py'} <= expected:
        raise InstallError('WorkBuddy plugin hook material is missing.')
    return metadata


def workbuddy_lease_pid(relative):
    match = re.fullmatch(r'\.in_use/([1-9][0-9]{0,9})', relative)
    return int(match[1]) if match and int(match[1]) <= 0x7fffffff else None


def verify_workbuddy_lease(fd, pid, info):
    """Validate only the macOS host's published cache marker, never process liveness."""
    if info.st_mode & 0o7111 or not 0 < info.st_size <= 128:
        raise InstallError('Native plugin host lease has an unsafe mode or size.')
    raw = os.read(fd, 129)
    if len(raw) != info.st_size:
        raise InstallError('Native plugin host lease changed during verification.')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
        if (not isinstance(value, dict) or set(value) != {'pid', 'procStart'}
                or type(value['pid']) is not int or value['pid'] != pid
                or not isinstance(value['procStart'], str)
                or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z', value['procStart'])):
            raise ValueError('invalid lease')
        datetime.datetime.strptime(value['procStart'], '%Y-%m-%dT%H:%M:%S.%fZ')
    except (ValueError, UnicodeError):
        raise InstallError('Native plugin host lease has an unsupported format.') from None


def verify_native_plugin(bundle, expected_manifest, plugin_dir):
    """Read explicit native files only; never inspect settings, invoke hooks or acquire an install lock."""
    if not re.fullmatch(r'[0-9a-f]{64}', expected_manifest or ''):
        raise InstallError('An exact paired manifest checksum is required.')
    if not plugin_dir.is_absolute() or '..' in plugin_dir.parts:
        raise InstallError('Provide the exact absolute native plugin directory.')
    manifest = verify_bundle(bundle, expected_manifest)
    metadata = manifest.get('workbuddyPlugin')
    if metadata is None:
        raise InstallError('This candidate has no paired WorkBuddy plugin.')
    expected = {str(PurePosixPath(e['path']).relative_to(PLUGIN_PATH)): e
                for e in manifest['files'] if e['path'].startswith(PLUGIN_PATH + '/')}
    directories = {'.', '.in_use'}
    for name in expected:
        directories.update(str(p) for p in PurePosixPath(name).parents)
    found, leases = [], []
    with ExitStack() as stack:
        # Pin every path component without resolving a link into another tree.
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        stack.callback(os.close, parent)
        for component in plugin_dir.parts[1:]:
            parent = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            stack.callback(os.close, parent)

        def visit(fd, relative):
            before = os.fstat(fd)
            is_dir = relative in directories
            lease_pid = workbuddy_lease_pid(relative) if relative not in expected else None
            if (before.st_uid != os.getuid() or before.st_mode & 0o022
                    or not (stat.S_ISDIR(before.st_mode) if is_dir else stat.S_ISREG(before.st_mode))
                    or not is_dir and before.st_nlink != 1):
                raise InstallError('Native plugin material has unsafe ownership, permissions or file type.')
            if is_dir:
                if relative == '.in_use' and before.st_mode & 0o7000:
                    raise InstallError('Native plugin host lease directory has an unsafe mode.')
                for name in sorted(os.listdir(fd)):
                    child = name if relative == '.' else relative + '/' + name
                    if child not in directories and child not in expected and workbuddy_lease_pid(child) is None:
                        raise InstallError('Native plugin contains unlisted material.')
                    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                    if child in directories:
                        flags |= os.O_DIRECTORY
                    child_fd = os.open(name, flags, dir_fd=fd)
                    stack.callback(os.close, child_fd)
                    visit(child_fd, child)
            elif lease_pid is not None:
                verify_workbuddy_lease(fd, lease_pid, before)
                leases.append(relative)
            else:
                entry = expected[relative]
                if before.st_size != entry['size']:
                    raise InstallError('Native plugin differs from the paired candidate.')
                digest = hashlib.sha256()
                remaining = entry['size'] + 1
                total = 0
                while remaining:
                    chunk = os.read(fd, min(remaining, 1024 * 1024))
                    if not chunk:
                        break
                    digest.update(chunk)
                    total += len(chunk)
                    remaining -= len(chunk)
                if (total != entry['size'] or digest.hexdigest() != entry['sha256']
                        or bool(before.st_mode & 0o111) != bool(entry.get('executable'))):
                    raise InstallError('Native plugin differs from the paired candidate.')
                found.append({'path': relative, 'sha256': digest.hexdigest(), 'size': before.st_size})
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise InstallError('Native plugin changed during verification.')

        visit(parent, '.')
    if {f['path'] for f in found} != set(expected):
        raise InstallError('Native plugin is missing paired files.')
    return {'ok': True, 'pluginFilesVerified': True, 'nativeEnableVerified': False, 'enabled': None,
            'hostLeaseFilesValidated': len(leases),
            'completeCandidateReadinessVerified': False, 'manifestSHA256': expected_manifest,
            'version': manifest['version'], 'revision': manifest['source']['revision'],
            'plugin': {'name': metadata['name'], 'version': metadata['version'], 'directory': str(plugin_dir)},
            'files': found, 'scope': 'Paired native plugin bytes and narrowly validated WorkBuddy cache leases only; lease liveness, native installation/enabled state and actual hook execution require separate evidence.'}


class MacHost:
    """OS boundary; tests replace this class without touching launchd or a real port."""
    def __init__(self, uid):
        self.domain = 'gui/' + str(uid)

    def command(self, *args):
        return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)

    def job(self, label):
        result = self.command('/bin/launchctl', 'print', self.domain + '/' + label)
        if result.returncode:
            return None
        match = re.search(r'^\s*pid = (\d+)\s*$', result.stdout, re.MULTILINE)
        program = re.search(r'^\s*program = (.+)$', result.stdout, re.MULTILINE)
        state = re.search(r'^\s*state = (.+)$', result.stdout, re.MULTILINE)
        runs = re.search(r'^\s*runs = (\d+)\s*$', result.stdout, re.MULTILINE)
        return {'pid': int(match.group(1)) if match else None, 'program': program.group(1).strip() if program else None,
                'state': state.group(1).strip() if state else None, 'runs': int(runs.group(1)) if runs else None}

    def listeners(self):
        result = self.command('/usr/sbin/lsof', '-nP', '-t', '-iTCP:37789', '-sTCP:LISTEN')
        if result.returncode not in (0, 1):
            raise InstallError('Cannot inspect the local service listener.')
        return {int(value) for value in result.stdout.split()}

    def alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def stop(self, label):
        if self.job(label) is not None:
            result = self.command('/bin/launchctl', 'bootout', self.domain + '/' + label)
            if result.returncode and self.job(label) is not None:
                raise InstallError('Could not unload the existing launch agent.')

    def start(self, plist):
        try:
            data = plistlib.loads(plist.read_bytes())
            label = data.get('Label') if isinstance(data, dict) else None
        except (OSError, ValueError):
            raise InstallError('Cannot read the launch agent identity.') from None
        if label not in LABELS or plist.name != label + '.plist':
            raise InstallError('Launch agent label does not match the managed service.')
        result = self.command('/bin/launchctl', 'bootstrap', self.domain, str(plist))
        if result.returncode:
            raise InstallError('launchd could not load the candidate.')
        # Background jobs may stay loaded with a speculative, non-demand spawn.
        # The old instance was already booted out; do not use -k or kill a job.
        result = self.command('/bin/launchctl', 'kickstart', self.domain + '/' + label)
        if result.returncode:
            raise InstallError('launchd loaded the job but could not explicitly start it.')

    def version(self, service):
        with service.open('rb') as stream:
            if stream.read(4) not in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
                raise InstallError('Service is not a macOS executable.')
        try:
            result = subprocess.run([str(service), '--version-json'], capture_output=True, text=True, timeout=5)
            if result.returncode:
                raise InstallError('Service does not support candidate identity verification.')
            return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, ValueError, OSError):
            raise InstallError('Cannot read service candidate identity.') from None

    def verify_app(self, path, app):
        verify_app_info(path, app)
        if mach_o_uuid(path / 'Contents/MacOS/cosmoedge-connect') != app['buildUUID'].upper():
            raise InstallError('App executable UUID differs from its paired manifest.')
        arguments = ['/usr/bin/codesign', '--verify', '--strict', '--verbose=2']
        if app['signing'] == 'apple':
            requirement = 'anchor apple generic and identifier "' + app['bundleIdentifier'] + '" and certificate leaf[subject.OU] = "' + app['teamIdentifier'] + '"'
            arguments.extend(['-R', requirement])
        if self.command(*arguments, str(path)).returncode:
            raise InstallError('CosmoEdge Connect app signature verification failed.')
        details = self.command('/usr/bin/codesign', '--display', '--verbose=4', str(path))
        fields = dict(re.findall(r'^(Identifier|TeamIdentifier|Signature)=(.*)$', details.stderr, re.MULTILINE))
        if details.returncode or fields.get('Identifier') != app['bundleIdentifier']:
            raise InstallError('CosmoEdge Connect code signing identifier differs from its app identity.')
        if app['signing'] == 'development-adhoc':
            if fields.get('Signature') != 'adhoc' or fields.get('TeamIdentifier') not in (None, 'not set'):
                raise InstallError('Development app must be explicitly ad hoc signed.')
        elif fields.get('TeamIdentifier') != app['teamIdentifier']:
            raise InstallError('CosmoEdge Connect app signing team differs from its paired identity.')

    def register_app(self, path):
        register_launch_services(path)

    def ready(self, token_path, identity, protocol):
        # This is an authenticated read only; it does not dispatch work to a device.
        token = token_path.read_text().strip()
        if protocol != 'cosmoedge.operations.v1':
            return False
        route = '/operations/v1/version'
        request = urllib.request.Request('http://127.0.0.1:37789' + route,
                                         headers={'Authorization': 'Bearer ' + token})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            with opener.open(request, timeout=2) as response:
                raw = response.read(1024 * 1024)
                data = json.loads(raw)
                actual = data.get('version', {})
                return response.status == 200 and data.get('ok') is True and data.get('protocol') == protocol and all(actual.get(k) == v for k, v in identity.items())
        except Exception:
            return False


class Installer:
    def __init__(self, home, host, python=None, skill_dir=None, timeout=20, ready_timeout=60):
        self.home = Path(home).absolute()
        self.uid = os.getuid()
        self.host = host
        self.python = Path(python or sys.executable).resolve()
        self.root = self.home / 'Library/Application Support/CosmoEdgeConnect'
        self.agents = self.home / 'Library/LaunchAgents'
        self.skill = Path(skill_dir).expanduser().absolute() if skill_dir else self.home / '.workbuddy/skills/cosmoedge-operations'
        if self.skill == self.home or self.home not in self.skill.parents or self.skill.name != 'cosmoedge-operations':
            raise InstallError('Skill destination must be a cosmoedge-operations directory under the current user home.')
        self.token = self.root / 'access.token'
        self.record = self.root / 'paired-install.json'
        self.python_path = self.root / 'python.path'
        self.pending = self.root / 'paired-pending.json'
        self.app = self.root / APP_NAME
        self.timeout = timeout
        self.ready_timeout = ready_timeout

    def safe_path(self, path):
        if path != self.home and self.home not in path.parents:
            raise InstallError('Installation target is outside the current user home.')
        parts = path.relative_to(self.home).parts
        current = self.home
        for part in ('',) + parts:
            if part:
                current = current / part
            if current.is_symlink():
                raise InstallError('Installation target cannot pass through a symbolic link.')
            if current.exists() and current.stat().st_uid != self.uid:
                raise InstallError('Installation target belongs to another user.')

    def directory(self, path, private=True):
        self.safe_path(path)
        if path.exists() and not path.is_dir():
            raise InstallError('An installation directory is occupied by a file.')
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        if private:
            path.chmod(0o700)

    def prepare(self):
        self.safe_path(self.root)
        self.safe_path(self.skill)
        self.safe_path(self.app)
        if self.app.exists():
            safe_app_tree(self.app, self.uid)
        for path in (self.root, self.root / 'runtime-state', self.root / 'logs', self.root / 'releases', self.root / 'backups'):
            self.directory(path)
        self.directory(self.agents, private=False)
        self.directory(self.skill.parent, private=False)
        for path in (self.token, self.record, self.python_path, self.pending, self.agents / (LABEL + '.plist')):
            self.safe_path(path)
            if path.exists() and not path.is_file():
                raise InstallError('An installation file is occupied by a non-regular path.')
        for name in ('service.log', 'error.log'):
            path = self.root / 'logs' / name
            self.safe_path(path)
            if path.exists():
                if not path.is_file():
                    raise InstallError('Unsafe service log path.')
                path.chmod(0o600)

    @contextmanager
    def locked(self, prepare=True):
        if prepare:
            self.prepare()
        else:
            self.safe_path(self.root)
            if not self.root.is_dir():
                raise InstallError('No paired installation exists.')
        lock_path = self.root / '.paired-install.lock'
        self.safe_path(lock_path)
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        import fcntl
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise InstallError('Another paired installation or lifecycle operation is running.') from None
            yield
        finally:
            os.close(descriptor)

    def provision_token(self):
        if self.token.exists():
            self.safe_path(self.token)
            info = self.token.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or not re.fullmatch(b'[0-9a-f]{64}\n?', self.token.read_bytes()):
                raise InstallError('Existing access token is invalid or is not owner-only; it was preserved.')
            return
        descriptor = os.open(self.token, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(secrets.token_hex(32) + '\n')
            stream.flush()
            os.fsync(stream.fileno())

    def jobs(self):
        return {label: self.host.job(label) for label in LABELS}

    def check_listener_ownership(self, jobs):
        pids = {job['pid'] for job in jobs.values() if job and job.get('pid')}
        if not self.host.listeners().issubset(pids):
            raise InstallError('Port 37789 is owned by an unmanaged process; no service was stopped.')

    def stop_all(self):
        jobs = self.jobs()
        self.check_listener_ownership(jobs)
        old_pids = {job['pid'] for job in jobs.values() if job and job.get('pid')}
        for label in LABELS:
            self.host.stop(label)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if not self.host.listeners() and not any(self.host.alive(pid) for pid in old_pids):
                return
            time.sleep(0.1)
        raise InstallError('Previous service PID or listener did not exit; candidate was not started.')

    def wait_ready(self):
        record = json.loads(self.record.read_text())
        manifest = verify_bundle(Path(record['release']), record['manifestSHA256'])
        identity = {'product': 'cosmoedge-connect', 'version': manifest['version'], 'revision': manifest['source']['revision'],
                    'modified': manifest['source']['modified'], 'platform': manifest['platform']}
        program = self.installed_program(record, manifest)
        deadline = time.monotonic() + self.ready_timeout
        while time.monotonic() < deadline:
            job = self.host.job(LABEL)
            if job and job.get('pid') and job.get('program') == str(program) and self.host.listeners() == {job['pid']} and self.host.ready(self.token, identity, manifest['service']['healthProtocol']):
                return
            time.sleep(0.2)
        raise InstallError('Candidate did not become the unique authenticated service listener.')

    def wait_restored(self, labels):
        if not labels:
            if self.host.listeners():
                raise InstallError('Recovery expected no running service, but the listener is still occupied.')
            return
        if labels != [LABEL] or not self.record.exists():
            raise InstallError('Recovery requires a paired CosmoEdge Connect candidate.')
        self.wait_ready()

    def snapshot(self, jobs):
        identifier = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + secrets.token_hex(5)
        backup = self.root / 'backups' / identifier
        backup.mkdir(mode=0o700)
        targets = self.recovery_targets()
        files = []
        for key, target in targets:
            self.safe_path(target)
            if target.exists():
                safe_tree(target, self.uid)
                if target.is_dir():
                    shutil.copytree(target, backup / key)
                else:
                    shutil.copy2(target, backup / key)
                for file in ([backup / key] if target.is_file() else sorted((backup / key).rglob('*'))):
                    if file.is_file():
                        files.append({'path': file.relative_to(backup).as_posix(), 'sha256': sha256(file)})
            else:
                files.append({'absent': key})
        data = {'schemaVersion': 1, 'id': identifier, 'skillPath': str(self.skill),
                'loadedLabels': [label for label, job in jobs.items() if job is not None], 'files': files}
        write_json(backup / 'backup.json', data)
        write_json(self.pending, {'backup': identifier, 'phase': 'prepared'})
        return backup

    def recovery_targets(self):
        return [('skill', self.skill), ('app', self.app), ('record', self.record), ('python.path', self.python_path)] + [(label + '.plist', self.agents / (label + '.plist')) for label in LABELS]

    def backup_data(self, backup):
        self.safe_path(backup)
        safe_tree(backup, self.uid)
        data = json.loads((backup / 'backup.json').read_text())
        if data.get('id') != backup.name or data.get('skillPath') != str(self.skill) or any(label not in LABELS for label in data.get('loadedLabels', [])):
            raise InstallError('Backup does not belong to this installation.')
        expected_targets = {key for key, _ in self.recovery_targets()}
        expected_files = set()
        expected_absent = set()
        for key in expected_targets:
            target = backup / key
            if not target.exists():
                expected_absent.add(key)
            elif target.is_file():
                expected_files.add(key)
            else:
                expected_files.update(p.relative_to(backup).as_posix() for p in target.rglob('*') if p.is_file())
        recorded_files = [item['path'] for item in data['files'] if 'path' in item]
        recorded_absent = [item['absent'] for item in data['files'] if 'absent' in item]
        if (set(recorded_files) != expected_files or len(recorded_files) != len(expected_files)
                or set(recorded_absent) != expected_absent or len(recorded_absent) != len(expected_absent)):
            raise InstallError('Recovery backup does not cover this product installation.')
        for item in data['files']:
            if 'path' in item:
                relative = PurePosixPath(item['path'])
                if relative.is_absolute() or '..' in relative.parts or sha256(backup / str(relative)) != item['sha256']:
                    raise InstallError('Recovery backup checksum failed.')
        return data

    def archive_target(self, target, archive):
        self.safe_path(target)
        if target.exists():
            safe_tree(target, self.uid)
            shutil.move(str(target), str(archive))

    def restore(self, backup):
        data = self.backup_data(backup)
        targets = self.recovery_targets()
        # Refuse unsafe imported material before changing transaction state or
        # stopping a healthy listener. archive_target repeats these checks later.
        for key, target in targets:
            self.safe_path(target)
            if target.exists():
                safe_tree(target, self.uid)
                if not (target.is_dir() if key in ('skill', 'app') else target.is_file()):
                    raise InstallError('Current recovery target has an unexpected file type: ' + key)
                if key == 'app':
                    safe_app_tree(target, self.uid)
        if (backup / 'record').is_file():
            previous = json.loads((backup / 'record').read_text())
            release = Path(previous['release'])
            self.safe_path(release)
            previous_manifest = verify_bundle(release, previous['manifestSHA256'])
            if previous.get('appPath') != str(self.app) or previous.get('skillPath') != str(self.skill):
                raise InstallError('Backup app identity belongs to another installation.')
            # Validate the recoverable app before stopping the current job.
            self.verify_app_material(backup / 'app', previous_manifest)
        write_json(self.pending, {'backup': backup.name, 'phase': 'restoring'})
        self.stop_all()
        displaced = backup / ('displaced-' + secrets.token_hex(5))
        displaced.mkdir(mode=0o700)
        for key, target in targets:
            self.archive_target(target, displaced / key)
            source = backup / key
            if source.exists():
                if source.is_dir():
                    shutil.copytree(source, target)
                else:
                    shutil.copy2(source, target)
        if self.record.exists():
            record, manifest = self.paired_manifest()
            self.installed_program(record, manifest)
            self.host.register_app(self.app)
        for label in data['loadedLabels']:
            plist = self.agents / (label + '.plist')
            if not plist.is_file():
                raise InstallError('A previously loaded service has no recoverable launch agent file.')
            self.host.start(plist)
        # Recover the listener contract before claiming completion. This read
        # does not claim device/business health or roll runtime databases back.
        self.wait_restored(data['loadedLabels'])
        if self.pending.exists():
            self.pending.unlink()
        write_json(backup / 'restored.json', {'restoredAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                            'loadedLabels': data['loadedLabels'], 'listenerRestored': True, 'runtimeStatePreserved': True})
        return {'restoredBackup': backup.name, 'loadedLabels': data['loadedLabels'], 'listenerRestored': True, 'runtimeStatePreserved': True}

    def install(self, bundle, expected=None):
        bundle = Path(bundle).absolute()
        if bundle == self.root or self.root in bundle.parents:
            raise InstallError('Install source must be outside the active installation root.')
        manifest = verify_bundle(bundle, expected)
        expected_platform = 'darwin/' + ('arm64' if platform.machine() == 'arm64' else 'amd64')
        if manifest['platform'] != expected_platform:
            raise InstallError('Candidate architecture does not match this Mac.')
        app = manifest['service'].get('macOSApp')
        self.host.verify_app(bundle / APP_PAYLOAD, app)
        version = self.host.version(bundle / service_path(manifest))
        if any(version.get(key) != value for key, value in {
                'product': 'cosmoedge-connect', 'version': manifest['version'], 'revision': manifest['source']['revision'],
                'modified': manifest['source']['modified'], 'platform': manifest['platform']}.items()):
            raise InstallError('Service build identity does not match the paired manifest.')
        if manifest.get('mcp'):
            mcp_version = self.host.version(bundle / manifest['mcp']['executablePath'])
            if mcp_version != version:
                raise InstallError('MCP build identity does not match the paired service.')
        if self.pending.exists():
            raise InstallError('An interrupted installation needs rollback before another installation.')
        jobs = self.jobs()
        self.check_listener_ownership(jobs)
        if sum(job is not None for job in jobs.values()) > 1:
            raise InstallError('Multiple managed launch agents are loaded; establish one recoverable baseline before installation.')
        for label, job in jobs.items():
            if job is not None and not (self.agents / (label + '.plist')).is_file():
                raise InstallError('A loaded managed service has no recoverable launch agent file.')
        if any(job is not None for job in jobs.values()) and not self.record.exists():
            raise InstallError('A loaded service has no paired installation record.')
        self.safe_path(self.app)
        if self.app.exists():
            safe_app_tree(self.app, self.uid)
            previous, previous_manifest = self.paired_manifest()
            if previous.get('appPath') != str(self.app):
                raise InstallError('Existing app is not owned by this paired installation.')
            self.installed_program(previous, previous_manifest)
        self.provision_token()
        identifier = manifest['version'] + '-' + sha256(bundle / 'manifest.json')[:12]
        release = self.root / 'releases' / identifier
        if release.exists():
            verify_bundle(release, sha256(bundle / 'manifest.json'))
        else:
            shutil.copytree(bundle, release)
            verify_bundle(release, sha256(bundle / 'manifest.json'))
        backup = self.snapshot(jobs)
        try:
            self.stop_all()
            write_json(self.pending, {'backup': backup.name, 'phase': 'stopped'})
            self.archive_target(self.app, backup / 'displaced-app')
            app_staging = self.root / ('.cosmoedge-connect-app-' + secrets.token_hex(6))
            try:
                shutil.copytree(release / APP_PAYLOAD, app_staging)
                for path in [app_staging] + list(app_staging.rglob('*')):
                    executable = path.relative_to(app_staging).as_posix() == 'Contents/MacOS/cosmoedge-connect'
                    path.chmod(0o700 if path.is_dir() or executable else 0o600)
                app_staging.rename(self.app)
            finally:
                if app_staging.exists():
                    shutil.rmtree(app_staging)
            staging = self.skill.parent / ('.cosmoedge-operations-' + secrets.token_hex(6))
            shutil.copytree(release / 'payload/skill', staging)
            write_private(self.python_path, (str(self.python) + '\n').encode())
            for path in [staging] + list(staging.rglob('*')):
                path.chmod(0o700 if path.is_dir() or path.name == 'cosmoedge-operations' else 0o600)
            self.archive_target(self.skill, backup / 'displaced-skill')
            staging.rename(self.skill)
            program = self.app / 'Contents/MacOS/cosmoedge-connect'
            plist = {'Label': LABEL, 'ProgramArguments': [str(program), '--state-root', str(self.root / 'runtime-state'),
                     '--token-file', str(self.token), '--listen', '127.0.0.1:37789'], 'RunAtLoad': True,
                     'KeepAlive': {'SuccessfulExit': False}, 'ProcessType': 'Background', 'ThrottleInterval': 10,
                     'Umask': 0o077, 'StandardOutPath': str(self.root / 'logs/service.log'),
                     'StandardErrorPath': str(self.root / 'logs/error.log')}
            plist['AssociatedBundleIdentifiers'] = [app['bundleIdentifier']]
            write_private(self.agents / (LABEL + '.plist'), plistlib.dumps(plist))
            record = {'schemaVersion': 1, 'version': manifest['version'], 'manifestSHA256': sha256(release / 'manifest.json'),
                      'source': manifest['source'], 'release': str(release), 'python': str(self.python),
                      'skillPath': str(self.skill), 'pythonPathSHA256': sha256(self.python_path), 'launcherSHA256': sha256(self.skill / 'scripts/cosmoedge-operations'),
                      'previousBackup': backup.name}
            record['appPath'] = str(self.app)
            write_json(self.record, record)
            write_json(self.pending, {'backup': backup.name, 'phase': 'files_changed'})
            self.installed_program(record, manifest)
            self.host.register_app(self.app)
            self.host.start(self.agents / (LABEL + '.plist'))
            self.wait_ready()
            self.pending.unlink()
            write_json(backup / 'completed.json', {'version': manifest['version'], 'manifestSHA256': record['manifestSHA256']})
            return {'installed': True, 'version': manifest['version'], 'source': manifest['source'],
                    'manifestSHA256': record['manifestSHA256'], 'backup': backup.name, 'python': str(self.python),
                    'uniqueListener': True, 'runtimeStatePreserved': True,
                    'macOSApp': app, 'localNetworkAuthorizationVerified': False}
        except Exception as error:
            try:
                phase = json.loads(self.pending.read_text()).get('phase') if self.pending.exists() else 'unknown'
                write_json(backup / 'failure.json', {'phase': phase,
                    'error': str(error) if isinstance(error, InstallError) else type(error).__name__,
                    'jobs': self.jobs(), 'listenerPids': sorted(self.host.listeners())})
            except Exception:
                pass  # Diagnostic I/O must never prevent attempting recovery.
            try:
                self.restore(backup)
            except Exception:
                raise InstallError('Candidate failed and automatic recovery is incomplete. Stop further changes and run rollback --backup ' + backup.name + '.') from None
            if isinstance(error, InstallError):
                raise InstallError(str(error) + ' Previous files and launch state were restored; backup ' + backup.name + '.') from None
            raise InstallError('Candidate installation failed. Previous files and launch state were restored; backup ' + backup.name + '.') from None

    def mcp_config(self, client_id):
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,39}', client_id):
            raise InstallError('Client ID must be 1-40 lowercase letters, digits or hyphens.')
        record, manifest = self.paired_manifest()
        if not manifest.get('mcp'):
            raise InstallError('This installed candidate has no MCP adapter.')
        release = Path(record['release'])
        return {'mcpServers': {'cosmoedge': {
            'command': str(release / manifest['mcp']['executablePath']),
            'args': ['--base-url', 'http://127.0.0.1:37789', '--token-file', str(self.token),
                     '--state-root', str(self.root / 'mcp-state' / client_id),
                     '--candidate-file', str(release / manifest['mcp']['candidatePath'])]}}}

    def paired_manifest(self):
        self.safe_path(self.record)
        if not self.record.is_file():
            raise InstallError('No paired candidate is installed.')
        record = json.loads(self.record.read_text())
        if record.get('skillPath') != str(self.skill):
            raise InstallError('Recorded Skill destination differs from this installation.')
        release = Path(record['release'])
        self.safe_path(release)
        manifest = verify_bundle(release, record['manifestSHA256'])
        return record, manifest

    def installed_program(self, record, manifest):
        if record.get('appPath') != str(self.app):
            raise InstallError('Recorded app path differs from this installation.')
        self.verify_app_material(self.app, manifest)
        return self.app / 'Contents/MacOS/cosmoedge-connect'

    def verify_app_material(self, app_path, manifest):
        self.safe_path(app_path)
        safe_app_tree(app_path, self.uid)
        expected = {str(PurePosixPath(e['path']).relative_to(APP_PAYLOAD)): e
                    for e in manifest['files'] if e['path'].startswith(APP_PAYLOAD + '/')}
        directories = {'.'}
        for name in expected:
            directories.update(str(p) for p in PurePosixPath(name).parents)
        found = set()
        for path in [app_path] + sorted(app_path.rglob('*')):
            info = path.lstat()
            relative = path.relative_to(app_path).as_posix()
            mode = stat.S_IMODE(info.st_mode)
            if path.is_dir():
                if relative not in directories:
                    raise InstallError('Installed app contains an unlisted directory: ' + relative)
                if mode != 0o700:
                    raise InstallError('Installed app directory is not owner-only: ' + relative)
                continue
            entry = expected.get(relative)
            if not entry or info.st_nlink != 1 or sha256(path) != entry['sha256'] or info.st_size != entry['size']:
                raise InstallError('Installed app differs from its paired manifest: ' + relative)
            expected_mode = 0o700 if relative == 'Contents/MacOS/cosmoedge-connect' else 0o600
            if mode != expected_mode:
                raise InstallError('Installed app file mode differs: ' + relative)
            found.add(relative)
        if found != set(expected):
            raise InstallError('Installed app is missing paired files.')
        self.host.verify_app(app_path, manifest['service']['macOSApp'])

    @contextmanager
    def skill_material(self, manifest):
        """Pin verified files before chmod; never follow imported links or alter host metadata."""
        expected = {str(PurePosixPath(e['path']).relative_to('payload/skill')): e
                    for e in manifest['files'] if e['path'].startswith('payload/skill/')}
        directories = {'.'}
        for name in expected:
            directories.update(str(p) for p in PurePosixPath(name).parents)
        self.safe_path(self.skill)
        entries = []
        found = set()
        with ExitStack() as stack:
            def visit(name, relative, parent_fd=None):
                before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                is_dir = relative in directories
                metadata = relative == '_user_meta.json'
                if before.st_uid != self.uid:
                    raise InstallError('Imported Skill belongs to another user: ' + relative)
                if stat.S_ISLNK(before.st_mode):
                    raise InstallError('Imported Skill contains a symbolic link: ' + relative)
                if not (stat.S_ISDIR(before.st_mode) if is_dir else stat.S_ISREG(before.st_mode)):
                    raise InstallError('Imported Skill contains an unexpected file type: ' + relative)
                if not is_dir and before.st_nlink != 1:
                    raise InstallError('Imported Skill contains a hard link: ' + relative)
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if is_dir:
                    flags |= os.O_DIRECTORY
                fd = os.open(name, flags, dir_fd=parent_fd)
                stack.callback(os.close, fd)
                opened = os.fstat(fd)
                if (before.st_dev, before.st_ino, before.st_mode, before.st_uid) != (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid):
                    raise InstallError('Imported Skill changed while being verified: ' + relative)
                entry = {'path': relative, 'fd': fd, 'parentFD': parent_fd, 'name': name, 'before': opened,
                         'mode': stat.S_IMODE(opened.st_mode), 'metadata': metadata,
                         'expectedMode': None if metadata else 0o700 if is_dir or relative == 'scripts/cosmoedge-operations' else 0o600}
                entries.append(entry)
                if is_dir:
                    for child in sorted(os.listdir(fd)):
                        child_relative = child if relative == '.' else relative + '/' + child
                        if child_relative not in expected and child_relative not in directories and child_relative != '_user_meta.json':
                            raise InstallError('Imported Skill contains an unlisted file: ' + child_relative)
                        visit(child, child_relative, fd)
                elif not metadata:
                    item = expected[relative]
                    digest = hashlib.sha256()
                    for chunk in iter(lambda: os.read(fd, 1024 * 1024), b''):
                        digest.update(chunk)
                    if opened.st_size != item['size'] or digest.hexdigest() != item['sha256']:
                        raise InstallError('Imported Skill differs from its paired candidate: ' + relative)
                    found.add(relative)
            visit(str(self.skill), '.')
            if found != set(expected):
                raise InstallError('Imported Skill is missing paired files: ' + ', '.join(sorted(set(expected) - found)))
            # Recheck every pinned inode after the complete content pass, before
            # any permission mutation. A pathname replacement cannot redirect fchmod.
            for entry in entries:
                current = os.stat(entry['name'], dir_fd=entry['parentFD'], follow_symlinks=False)
                before = entry['before']
                fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                if any(getattr(current, key) != getattr(before, key) for key in fields):
                    raise InstallError('Imported Skill changed while being verified: ' + entry['path'])
            yield entries

    @staticmethod
    def skill_accepted_modes(entry):
        if entry['metadata']:
            return None
        # A host-issued `chmod +x` can add only group/other execute bits to
        # this content-verified launcher. Its parent directories remain 0700;
        # no extra read/write or special bits, or other files, are admitted.
        if entry['path'] == 'scripts/cosmoedge-operations':
            return (0o700, 0o701, 0o710, 0o711)
        return (entry['expectedMode'],)

    @classmethod
    def skill_mode_accepted(cls, entry):
        modes = cls.skill_accepted_modes(entry)
        return modes is None or entry['mode'] in modes

    @classmethod
    def skill_modes(cls, entries):
        return [{'path': entry['path'], 'mode': format(entry['mode'], '04o'),
                 'normalizedMode': None if entry['metadata'] else format(entry['expectedMode'], '04o'),
                 'acceptedModes': None if entry['metadata'] else [format(mode, '04o') for mode in cls.skill_accepted_modes(entry)],
                 'modeAccepted': None if entry['metadata'] else cls.skill_mode_accepted(entry),
                 'hostMetadata': entry['metadata']} for entry in entries]

    def finalize_skill_import(self):
        if self.pending.exists():
            raise InstallError('An interrupted installation needs rollback before finalizing a Skill import.')
        record, manifest = self.paired_manifest()
        with self.skill_material(manifest) as entries:
            changed = []
            for entry in entries:
                if not entry['metadata'] and entry['mode'] != entry['expectedMode']:
                    os.fchmod(entry['fd'], entry['expectedMode'])
                    changed.append(entry['path'])
        with self.skill_material(manifest) as entries:
            modes = self.skill_modes(entries)
            if any(not entry['metadata'] and entry['mode'] != entry['expectedMode'] for entry in entries):
                raise InstallError('Imported Skill permissions changed before finalization completed.')
        return {'finalized': True, 'version': manifest['version'], 'manifestSHA256': record['manifestSHA256'],
                'skillContentVerified': True, 'skillPermissionsVerified': True, 'changedModes': changed,
                'skillModes': modes, 'hostMetadataPreserved': True, 'runtimeStatePreserved': True}

    def status(self):
        jobs = self.jobs()
        result = {'jobs': jobs, 'listenerPids': sorted(self.host.listeners()), 'pendingRecovery': self.pending.exists(),
                  'installed': self.record.exists(), 'pairingVerified': False, 'pairingFailures': [], 'skillModes': []}
        if not result['installed']:
            result['pairingFailures'].append('No paired candidate is installed.')
            return result
        try:
            record, manifest = self.paired_manifest()
            release = Path(record['release'])
            result.update({'version': manifest['version'], 'source': manifest['source'], 'manifestSHA256': record['manifestSHA256'],
                           'previousBackup': record['previousBackup'], 'python': record['python']})
            if manifest.get('workbuddyPlugin'):
                plugin = manifest['workbuddyPlugin']
                result['workbuddyPlugin'] = {'name': plugin['name'], 'version': plugin['version'], 'required': True,
                                            'pluginFilesVerified': False, 'nativeEnableVerified': False, 'enabled': None}
            with self.skill_material(manifest) as entries:
                result['skillModes'] = self.skill_modes(entries)
                for entry in entries:
                    if not self.skill_mode_accepted(entry):
                        result['pairingFailures'].append('Imported Skill mode differs: ' + entry['path'] +
                            ' (' + format(entry['mode'], '04o') + ', accepted ' +
                            ', '.join(format(mode, '04o') for mode in self.skill_accepted_modes(entry)) +
                            '); run finalize-skill-import after confirming this candidate.')
            plist_path = self.agents / (LABEL + '.plist')
            self.safe_path(plist_path)
            plist = plistlib.loads(plist_path.read_bytes())
            expected_program = str(self.installed_program(record, manifest))
            app = manifest['service'].get('macOSApp')
            result['macOSApp'] = app
            result['localNetworkAuthorizationVerified'] = False
            expected_args = [expected_program, '--state-root', str(self.root / 'runtime-state'), '--token-file', str(self.token), '--listen', '127.0.0.1:37789']
            if plist.get('Label') != LABEL or plist.get('ProgramArguments') != expected_args:
                raise InstallError('Installed launch agent differs from its paired service.')
            if plist.get('AssociatedBundleIdentifiers', []) != [app['bundleIdentifier']]:
                raise InstallError('Launch agent is not associated with its own paired CosmoEdge Connect app.')
            if jobs[LABEL] is not None and jobs[LABEL].get('program') != expected_program:
                raise InstallError('Loaded launch agent is running a different service candidate.')
            launcher = self.skill / 'scripts/cosmoedge-operations'
            self.safe_path(launcher)
            self.safe_path(self.python_path)
            if sha256(launcher) != record['launcherSHA256'] or sha256(self.python_path) != record['pythonPathSHA256']:
                raise InstallError('Installed launcher differs from its recorded interpreter binding.')
            for path in (self.token, self.python_path, self.record, plist_path):
                self.safe_path(path)
                mode = stat.S_IMODE(path.stat().st_mode)
                if mode != 0o600:
                    result['pairingFailures'].append('Installation file mode differs: ' + path.name + ' (' + format(mode, '04o') + ', expected 0600).')
            if result['pendingRecovery']:
                result['pairingFailures'].append('An interrupted installation needs rollback.')
        except (InstallError, OSError, ValueError, KeyError) as error:
            result['pairingFailures'].append(str(error) if isinstance(error, InstallError) else 'Installation metadata or filesystem verification failed.')
        result['pairingVerified'] = not result['pairingFailures']
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--skill-dir', type=Path, help='existing WorkBuddy Skill root (defaults to ~/.workbuddy/skills/cosmoedge-operations)')
    commands = parser.add_subparsers(dest='command', required=True)
    install = commands.add_parser('install')
    install.add_argument('--bundle', type=Path, required=True)
    install.add_argument('--expected-manifest-sha256', help='checksum from the trusted candidate handoff')
    plugin = commands.add_parser('verify-plugin', help='read-only: compare an explicit native plugin directory with a frozen bundle; does not verify enablement')
    plugin.add_argument('--bundle', type=Path, required=True)
    plugin.add_argument('--expected-manifest-sha256', required=True)
    plugin.add_argument('--plugin-dir', type=Path, required=True)
    commands.add_parser('status')
    mcp = commands.add_parser('mcp-config', help='print secret-free stdio configuration for the current paired release')
    mcp.add_argument('--client-id', required=True, help='unique local client name, such as codex or claude')
    commands.add_parser('finalize-skill-import', help='verify imported Skill contents, then restore candidate owner-only permissions')
    commands.add_parser('stop')
    commands.add_parser('start')
    commands.add_parser('restart')
    rollback = commands.add_parser('rollback')
    rollback.add_argument('--backup', help='backup ID; defaults to pending recovery or latest installation previousBackup')
    args = parser.parse_args()
    if args.command == 'verify-plugin':
        try:
            # No Installer, MacHost, installation lock, umask change, or settings read.
            result = verify_native_plugin(args.bundle, args.expected_manifest_sha256, args.plugin_dir)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0
        except (InstallError, OSError, ValueError, KeyError, TypeError):
            print(json.dumps({'ok': False, 'pluginFilesVerified': False, 'nativeEnableVerified': False,
                              'code': 'plugin_verification_failed'}), file=sys.stderr)
            return 1
    if sys.platform != 'darwin' or os.getuid() == 0:
        parser.error('Run this macOS installer as the logged-in desktop user, never root.')
    os.umask(0o077)
    installer = Installer(Path.home(), MacHost(os.getuid()), skill_dir=args.skill_dir)
    try:
        with installer.locked(prepare=args.command not in ('status', 'mcp-config', 'finalize-skill-import')):
            if args.command == 'install':
                result = installer.install(args.bundle, args.expected_manifest_sha256)
            elif args.command == 'status':
                result = installer.status()
            elif args.command == 'mcp-config':
                result = installer.mcp_config(args.client_id)
            elif args.command == 'finalize-skill-import':
                result = installer.finalize_skill_import()
            elif args.command == 'rollback':
                identifier = args.backup
                if not identifier:
                    if installer.pending.exists():
                        identifier = json.loads(installer.pending.read_text())['backup']
                    elif installer.record.exists():
                        identifier = json.loads(installer.record.read_text())['previousBackup']
                if not identifier or not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}', identifier):
                    raise InstallError('No valid recovery backup was selected.')
                result = installer.restore(installer.root / 'backups' / identifier)
            else:
                if installer.pending.exists():
                    raise InstallError('An interrupted installation needs rollback first.')
                if args.command in ('start', 'restart'):
                    status = installer.status()
                    if not status['installed']:
                        raise InstallError('No paired candidate is installed.')
                    if not status['pairingVerified']:
                        raise InstallError('Candidate pairing failed: ' + '; '.join(status['pairingFailures']))
                if args.command in ('stop', 'restart'):
                    installer.stop_all()
                if args.command in ('start', 'restart'):
                    if args.command == 'start' and installer.host.job(LABEL) is not None:
                        installer.wait_ready()
                    else:
                        installer.check_listener_ownership(installer.jobs())
                        if installer.host.listeners():
                            raise InstallError('A different managed job still owns the listener; use restart for a coordinated switch.')
                        installer.host.start(installer.agents / (LABEL + '.plist'))
                        installer.wait_ready()
                result = installer.status()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1 if args.command == 'status' and not result['pairingVerified'] else 0
    except (InstallError, OSError, ValueError, KeyError) as error:
        # No raw subprocess output, token, device credential, or traceback is printed.
        message = str(error) if isinstance(error, InstallError) else 'Installation metadata or filesystem operation failed; existing runtime state was preserved.'
        print(json.dumps({'ok': False, 'message': message}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
