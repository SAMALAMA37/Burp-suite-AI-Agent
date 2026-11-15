"""Package reviewed Git-tracked source without local state or dependencies."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BLOCKED = {'.git', '.state', 'node_modules', '__pycache__', '.cache', '.pnpm-store',
           'artifacts', 'test-tmp', '9router-experiment', 'release'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--include-untracked', action='store_true',
                        help='Include reviewed non-ignored files before the first commit.')
    args = parser.parse_args()
    command = ['git', 'ls-files', '-z']
    if args.include_untracked:
        command += ['--cached', '--others', '--exclude-standard']
    result = subprocess.run(command, cwd=ROOT, check=True, stdout=subprocess.PIPE)
    names = sorted(set(name for name in result.stdout.decode('utf-8').split('\0') if name))
    if not names or 'BurpAI_v4_Extension.py' not in names:
        raise SystemExit('Stage the reviewed source files in Git before packaging.')
    for name in names:
        path = PurePosixPath(name)
        if (BLOCKED.intersection(path.parts) or path.name.startswith(('.env', '.burpai'))
                or name == 'nine_router/runtime.json'
                or path.suffix.lower() in {'.log', '.jar', '.zip', '.tgz', '.pyc', '.class', '.db', '.pem', '.key'}
                or (ROOT / name).is_symlink()):
            raise SystemExit('Refusing runtime/private/generated path: ' + name)
    output = ROOT / 'release'
    output.mkdir(exist_ok=True)
    archive = output / 'BurpAI-4.5-source.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
        for name in names:
            entry = zipfile.ZipInfo('BurpAI_4_5/' + name, (2026, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            bundle.writestr(entry, (ROOT / name).read_bytes())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / 'SHA256SUMS.txt').write_text(digest + '  ' + archive.name + '\n', encoding='utf-8')
    print('Packaged %d files: %s' % (len(names), archive))


if __name__ == '__main__':
    main()
