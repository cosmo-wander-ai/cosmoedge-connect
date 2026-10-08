"""Build a paired Windows development package from the current source tree."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def candidate_version(value):
    # Go parses -ldflags again, so candidate identity must remain one value.
    # Keep this contract aligned with the Windows installer's release names.
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,79}', value):
        raise argparse.ArgumentTypeError('version must be 1-80 ASCII letters, digits, dots, underscores or hyphens, starting with a letter or digit')
    return value


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_powershell(path, text):
    # Path.write_text(newline=...) is unavailable in supported Python 3.9.
    with path.open('w', encoding='utf-8-sig', newline='\r\n') as stream:
        stream.write(text)


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT).decode('utf-8').strip()


def inventory():
    raw = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT)
    return {name: sha(ROOT / name) for name in sorted(set(raw.decode().split('\0'))) if name and (ROOT / name).is_file()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--go', default='go')
    parser.add_argument('--with-mcp', action='store_true', help='include the paired local stdio MCP adapter')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', required=True, type=candidate_version)
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or ROOT in output.parents or output.exists():
        raise ValueError('Use a new output directory outside the source tree')
    revision = git('rev-parse', 'HEAD')
    modified = bool(git('status', '--porcelain'))
    sources = inventory()
    output.mkdir(parents=True)
    binary = output / 'payload' / 'cosmoedge-connect.exe'
    binary.parent.mkdir()
    flags = ' '.join('-X github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo.' + k + '=' + v for k, v in {
        'Version': args.version, 'SourceRevision': revision, 'SourceModified': str(modified).lower()}.items())
    env = dict(os.environ, GOOS='windows', GOARCH='amd64', CGO_ENABLED='0', GOWORK='off')
    subprocess.run([args.go, 'build', '-trimpath', '-buildvcs=false', '-ldflags', flags,
                    '-o', str(binary), './cmd/cosmoedge-connect'], cwd=ROOT, env=env, check=True)
    candidate = dict(schemaVersion=1, version=args.version, revision=revision, modified=modified,
                     platform='windows/amd64', serviceSHA256=sha(binary))
    if args.with_mcp:
        mcp = output / 'payload' / 'cosmoedge-mcp.exe'
        subprocess.run([args.go, 'build', '-trimpath', '-buildvcs=false', '-ldflags', flags,
                        '-o', str(mcp), './cmd/cosmoedge-mcp'], cwd=ROOT, env=env, check=True)
        candidate['mcpSHA256'] = sha(mcp)
    skill = output / 'payload' / 'skill'
    shutil.copytree(ROOT / 'integrations/workbuddy/skills/cosmoedge-operations', skill,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    deploy = ROOT / 'integrations/workbuddy/deploy/windows'
    for name in ['cosmoedge-operations.cmd', 'cosmoedge-operations.ps1']:
        source = deploy / name
        target = skill / 'scripts' / name
        if name.endswith('.ps1'):
            write_powershell(target, source.read_text(encoding='utf-8-sig'))
        else:
            shutil.copy2(source, target)
    candidate['clientFiles'] = {p.relative_to(skill).as_posix(): sha(p) for p in sorted((skill / 'scripts').rglob('*.py'))}
    (skill / 'candidate.json').write_text(json.dumps(candidate, indent=2) + '\n', encoding='utf-8')
    if args.with_mcp:
        shutil.copy2(skill / 'candidate.json', output / 'payload' / 'mcp-candidate.json')
        shutil.copytree(ROOT / 'skills/cosmoedge-operations', output / 'skills/cosmoedge-operations',
                        symlinks=True, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.DS_Store'))
    shutil.copy2(deploy / 'provision-token.py', output / 'provision-token.py')
    for name in ('LICENSE', 'NOTICE'):
        shutil.copy2(ROOT / name, output / name)
    shutil.copytree(ROOT / 'third_party/licenses', output / 'third_party/licenses', symlinks=True)
    for name in ['install-windows.ps1', 'cosmoedge-connect-control.ps1']:
        write_powershell(output / name, (deploy / name).read_text(encoding='utf-8-sig'))
    with zipfile.ZipFile(output / 'cosmoedge-operations.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(skill.rglob('*')):
            if path.is_file():
                archive.write(path, 'cosmoedge-operations/' + path.relative_to(skill).as_posix())
    (output / 'source-files.json').write_text(json.dumps(sources, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    if any(path.is_symlink() for path in output.rglob('*')):
        raise ValueError('Package material cannot contain symbolic links')
    manifest = dict(schemaVersion=1, candidate=candidate, sourceTree=git('rev-parse', 'HEAD^{tree}'),
                    files=[dict(path=p.relative_to(output).as_posix(), sha256=sha(p), bytes=p.stat().st_size)
                           for p in sorted(output.rglob('*')) if p.is_file()])
    if sources != inventory():
        raise ValueError('Source changed during build; do not install this package')
    path = output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(bundle=str(output), manifestSHA256=sha(path), candidate=candidate)))


if __name__ == '__main__':
    main()
