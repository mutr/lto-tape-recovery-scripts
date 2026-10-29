#!/usr/bin/env python3
"""Selective read-only DIVA tape recovery using diva_catalog_scan.py SQLite.

Requires mt/mtx (mt-st and mtx). Tape contents are never modified.
Examples:
  python3 diva_restore_one.py --db /root/tape-recovery/600148L6/catalog/catalog.sqlite3 --list --name 'PR616680'
  python3 diva_restore_one.py --db /root/tape-recovery/600148L6/catalog/catalog.sqlite3 --id 1,2
"""
import argparse
import hashlib
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_RECORD = 16 * 1024 * 1024 - 1


def cmd(*argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def loaded_barcode(changer):
    output = cmd('mtx', '-f', changer, 'status')
    m = re.search(r'Data Transfer Element\s+0:Full[^\n]*VolumeTag\s*=\s*([^\s]+)', output)
    if not m:
        raise RuntimeError('Drive 0 not full or barcode not readable; mtx output:\n' + output)
    return m.group(1)


def restore(row, args):
    obj_id, barcode, metadata_file, data_file, original, place, status = row
    destination = Path(place)
    if destination.is_symlink() or any(p.is_symlink() for p in destination.parents):
        raise RuntimeError(f'Symlink in destination: {destination}')
    # Ensure backup is read into exact stored path, not a duplicate layout.
    if destination.exists():
        if not destination.is_file():
            raise RuntimeError(f'Destination not regular file: {destination}')
        if destination.stat().st_size and not args.replace:
            raise RuntimeError(f'Refusing to replace nonempty file without --replace: {destination}')
    if status == 'restored' and not args.replace:
        raise RuntimeError(f'Object {obj_id} already marked restored (use --replace if intentional)')

    destination.parent.mkdir(parents=True, exist_ok=True)
    print(f'[{obj_id}] {original} (tape file {data_file})', flush=True)
    cmd('mt', '-f', args.tape, 'rewind')
    cmd('mt', '-f', args.tape, 'fsf', str(data_file))

    temp_path = None
    bytes_written = 0
    blocks = 0
    digest = hashlib.sha256()
    try:
        with tempfile.NamedTemporaryFile(prefix=f'.{destination.name}.', suffix='.part',
                                         dir=destination.parent, delete=False) as tmp:
            temp_path = Path(tmp.name)
            fd = os.open(args.tape, os.O_RDONLY)
            try:
                while True:
                    b = os.read(fd, args.buffer)
                    if not b:  # Tape filemark, not end of whole tape
                        break
                    if bytes_written + len(b) > args.max_bytes:
                        raise RuntimeError(f'Maximum file size {args.max_bytes} exceeded (use --max-gib)')
                    tmp.write(b)
                    digest.update(b)
                    blocks += 1
                    bytes_written += len(b)
                    if blocks % 4096 == 0:
                        print(f'  {bytes_written / (1024**3):.2f} GiB / {blocks} records', flush=True)
            finally:
                os.close(fd)
            tmp.flush()
            os.fsync(tmp.fileno())
        if bytes_written == 0:
            raise RuntimeError('Empty tape file: refusing to replace placeholder')
        with temp_path.open('rb') as f:
            magic = f.read(4)
        if magic != bytes.fromhex('060e2b34'):
            raise RuntimeError(f'Missing expected MXF SMPTE UL at start: {magic.hex()}')
        # Prevent unlink/overwrite of restored source unless specifically requested.
        if destination.exists() and destination.stat().st_size != 0 and not args.replace:
            raise RuntimeError('Destination changed during recovery; refusing overwrite')
        if args.replace and destination.exists() and destination.stat().st_size != 0:
            raise RuntimeError('For safety, move existing nonempty file aside manually before --replace')
        os.replace(temp_path, destination)
        temp_path = None
        print(f'  DONE: {destination}\n  Size: {bytes_written}\n  Records: {blocks}\n  SHA256: {digest.hexdigest()}', flush=True)
        return bytes_written, digest.hexdigest()
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--db', required=True, type=Path)
    ap.add_argument('--tape', default='/dev/nst0')
    ap.add_argument('--changer', default='/dev/sg3')
    ap.add_argument('--id', help='One or several comma-separated SQLite object IDs, e.g. 1,3,8')
    ap.add_argument('--name', help='Search filename or original_path (substring)')
    ap.add_argument('--list', action='store_true', help='Show matching catalog rows only')
    ap.add_argument('--replace', action='store_true', help='Allow replacement of empty placeholders marked restored')
    ap.add_argument('--buffer', type=int, default=1024 * 1024, help='Read buffer in bytes; default 1 MiB')
    ap.add_argument('--max-gib', type=float, default=100.0, help='Safety maximum per recovered file, default 100 GiB')
    args = ap.parse_args()
    if not (65536 <= args.buffer <= MAX_RECORD) or args.max_gib <= 0:
        ap.error('Invalid --buffer or --max-gib')
    args.max_bytes = int(args.max_gib * 1024**3)
    if not args.id and not args.name and not args.list:
        ap.error('Provide --id, or --name, or --list')
    ids = []
    if args.id:
        try:
            ids = list(dict.fromkeys(int(x.strip()) for x in args.id.split(',')))
            if not ids or any(x < 1 for x in ids):
                raise ValueError
        except ValueError:
            ap.error('--id must be comma-separated positive integers')
    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    try:
        cols = ['id', 'tape_barcode', 'metadata_file', 'data_file', 'original_path', 'placeholder_path', 'status']
        q = 'SELECT ' + ','.join(cols) + ' FROM objects'
        filters, params = [], []
        if ids:
            filters.append('id IN (' + ','.join('?' for _ in ids) + ')')
            params.extend(ids)
        if args.name:
            filters.append('(filename LIKE ? OR original_path LIKE ?)')
            params.extend(['%' + args.name + '%'] * 2)
        if filters:
            q += ' WHERE ' + ' AND '.join(filters)
        q += ' ORDER BY data_file ASC'
        rows = [tuple(row) for row in conn.execute(q, params)]
        for row in rows:
            print(f'id={row[0]} file={row[3]} status={row[6]} path={row[4]}')
        if args.list:
            print(f'{len(rows)} catalog entries')
            return 0
        if not rows:
            raise RuntimeError('Nothing matched')
        if args.id and len(rows) != len(ids):
            raise RuntimeError(f'Found {len(rows)} entries but requested {len(ids)} IDs')
        if args.name and not args.id and len(rows) != 1:
            raise RuntimeError('Name matches several objects; choose --id after --list')
        barcodes = {r[1] for r in rows}
        if len(barcodes) != 1:
            raise RuntimeError('Multiple barcodes selected')
        actual = loaded_barcode(args.changer)
        wanted = next(iter(barcodes))
        if actual != wanted:
            raise RuntimeError(f'Wrong cartridge: expected {wanted}, loaded {actual}')
        errors = 0
        for row in rows:
            try:
                size, sha = restore(row, args)
                with conn:
                    conn.execute('UPDATE objects SET status=?, size_bytes=? WHERE id=?', ('restored', size, row[0]))
            except (OSError, subprocess.CalledProcessError, RuntimeError) as e:
                errors += 1
                print(f'ERROR restoring id={row[0]}: {e}', file=sys.stderr)
                break  # fail closed, especially on hardware errors
        return 1 if errors else 0
    finally:
        conn.close()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, sqlite3.Error, RuntimeError, subprocess.CalledProcessError) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(1)
