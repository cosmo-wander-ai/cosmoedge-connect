#!/usr/bin/env python3
"""Check local Markdown link targets in the current source tree."""
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def main():
    result = subprocess.run(
        ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
        cwd=ROOT, check=True, capture_output=True, text=True)
    files = sorted({ROOT / name for name in result.stdout.split('\0')
                    if name.endswith('.md') and (ROOT / name).is_file()})
    failures = []
    checked = 0
    for path in files:
        fence = None
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            marker = re.match(r'^\s*(`{3,}|~{3,})', line)
            if marker:
                token = marker.group(1)[0]
                fence = None if fence == token else token
                continue
            if fence:
                continue
            line = re.sub(r'`[^`]*`', '', line)
            for match in re.finditer(r'!?\[[^\]]*\]\((<[^>]+>|[^\s)]+)(?:\s+"[^"]*")?\)', line):
                target = match.group(1).strip('<>')
                parsed = urlsplit(target)
                if parsed.scheme or parsed.netloc or not parsed.path:
                    continue
                checked += 1
                resolved = (path.parent / unquote(parsed.path)).resolve()
                if not resolved.is_relative_to(ROOT) or not resolved.exists():
                    failures.append(f'{path.relative_to(ROOT)}:{number}: missing or nonportable link {target}')
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        return 1
    print(f'Checked {checked} local links in {len(files)} Markdown files.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
