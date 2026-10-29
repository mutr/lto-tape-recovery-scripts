#!/usr/bin/env python3
"""Read-only emergency acquisition of Proxmox Backup Server LTO tape files.

This preserves the exact tape-file byte streams and their boundaries; it does
NOT yet decode PBS chunk/snapshot archive internals into a PBS datastore.
Run as root on Linux with mt-st, a compatible SCSI tape drive and spare disk.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

BLOCK = 8 * 1024 * 1024

def mt(device, *args):
    cmd = ['mt', '-f', device, *map(str, args)]
    subprocess.run(cmd, check=True)

def barcode_in_changer(changer, barcode):
    res = subprocess.run(['mtx', '-f', changer, 'status'], capture_output=True,
                         text=True, check=True)
    line = next((line for line in res.stdout.splitlines()
                 if line.startswith('Data Transfer Element 0:')), '')
    if not line or not re.search(r'VolumeTag\s*=\s*' + re.escape(barcode) + r'\s*$', line):
        raise RuntimeError('Wrong tape in drive: ' + (line or 'drive not loaded'))

def load_manifest(path, barcode):
    if path.exists():
        m = json.loads(path.read_text())
        if m.get('barcode') != barcode:
            raise RuntimeError('Manifest belongs to another barcode')
        return m
    return {'schema': 1, 'barcode': barcode, 'files': {}}

def save_manifest(path, m):
    temp = path.with_suffix('.json.tmp')
    with temp.open('w') as f:
        json.dump(m, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)

def dump_file(device, outfile, limit):
    temp = outfile.with_suffix(outfile.suffix + '.partial')
    if temp.exists():
        raise RuntimeError(f'Incomplete extraction exists: {temp}; move/remove it before retry')
    digest = hashlib.sha256()
    total = 0
    count = 0
    try:
        with open(device, 'rb', buffering=0) as tape, temp.open('xb', buffering=0) as out:
            while True:
                data = tape.read(BLOCK)
                if not data:  # SCSI filemark (at least for non-empty tape files)
                    break
                if total + len(data) > limit:
                    raise RuntimeError('Safety size limit reached; --max-gib can be increased')
                out.write(data)
                digest.update(data)
                total += len(data)
                count += 1
                if count % 128 == 0:
                    print(f'    {total / (1024**2):.1f} MiB', flush=True)
        os.replace(temp, outfile)
    except Exception:
        print(f'Incomplete output retained at {temp}', file=sys.stderr)
        raise
    return {'size_bytes': total, 'sha256': digest.hexdigest(), 'records': count,
            'path': outfile.name, 'completed_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--tape', default='/dev/nst0')
    p.add_argument('--changer', default='/dev/sg3')
    p.add_argument('--barcode', required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--first-file', type=int, default=0)
    p.add_argument('--last-file', type=int, required=True,
                   help='Inclusive; known tape file index. Never guess EOT on a valuable tape.')
    p.add_argument('--max-gib', type=float, default=64,
                   help='Maximum single tape file size; default 64 GiB')
    p.add_argument('--verify-existing', action='store_true', help='Verify SHA-256 of prior captures')
    args = p.parse_args()
    if args.first_file < 0 or args.last_file < args.first_file or args.max_gib <= 0:
        p.error('Invalid file range / size limit')
    if not re.fullmatch(r'[A-Za-z0-9_-]{3,32}', args.barcode):
        p.error('Bad barcode')
    args.out.mkdir(parents=True, exist_ok=True)
    manifest_path = args.out / 'manifest.json'
    manifest = load_manifest(manifest_path, args.barcode)
    barcode_in_changer(args.changer, args.barcode)
    print(f'Tape verified: {args.barcode}, reading {args.first_file}..{args.last_file}', flush=True)
    print('READ ONLY: no tape-writing commands will be used.', flush=True)
    for n in range(args.first_file, args.last_file + 1):
        filename = f'file-{n:06d}.bin'
        output = args.out / filename
        saved = manifest['files'].get(str(n))
        if saved and output.is_file():
            if args.verify_existing:
                with output.open('rb') as f:
                    h = hashlib.file_digest(f, 'sha256').hexdigest()
                if h != saved['sha256'] or output.stat().st_size != saved['size_bytes']:
                    raise RuntimeError(f'Existing file {output} hash or size mismatch')
            print(f'[{n}] already captured: {saved["size_bytes"]:,} bytes', flush=True)
            continue
        if output.exists():
            raise RuntimeError(f'{output} exists without a manifest entry; refusing to overwrite')
        # Rewind and seek by tape file number: deterministic after interruption.
        barcode_in_changer(args.changer, args.barcode)
        print(f'[{n}] seeking...', flush=True)
        mt(args.tape, 'rewind')
        if n:
            mt(args.tape, 'fsf', n)
        result = dump_file(args.tape, output, int(args.max_gib * (1024**3)))
        manifest['files'][str(n)] = result
        save_manifest(manifest_path, manifest)
        print(f'[{n}] saved {result["size_bytes"]:,} bytes sha256={result["sha256"]}', flush=True)
        if result['size_bytes'] == 0:
            print('Empty tape file/filemark; stopping to avoid reading beyond EOD.', file=sys.stderr)
            break
    print('Done. Manifest:', manifest_path)
    print('NOTE: raw tape-file acquisition only; PBS chunk/index decoding is not implemented.')

if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        sys.exit(f'ERROR: {exc}')
