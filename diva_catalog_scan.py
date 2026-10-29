#!/usr/bin/env python3
"""Read DIVA metadata records directly from an LTO tape into SQLite and 0-byte placeholders.

Confirmed layout for 600148L6: tape file 0 volume label; 1 metadata;
2 data; 3 separator; 4 metadata; 5 data; 6 separator; etc.
No tape writes. A resumable scanner; unknown layouts fail closed.
"""
import argparse
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path, PurePosixPath

SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (
 id INTEGER PRIMARY KEY,
 tape_barcode TEXT NOT NULL,
 metadata_file INTEGER NOT NULL,
 data_file INTEGER NOT NULL,
 original_dir TEXT NOT NULL,
 filename TEXT NOT NULL,
 original_path TEXT NOT NULL,
 placeholder_path TEXT NOT NULL,
 size_bytes INTEGER,
 status TEXT NOT NULL DEFAULT 'placeholder',
 UNIQUE(tape_barcode, metadata_file)
);
CREATE INDEX IF NOT EXISTS idx_objects_filename ON objects(filename);
CREATE INDEX IF NOT EXISTS idx_objects_original_path ON objects(original_path);
CREATE INDEX IF NOT EXISTS idx_objects_tape_position ON objects(tape_barcode, data_file);
"""


def run_mt(device, *args):
    cmd = ['mt', '-f', device, *map(str, args)]
    subprocess.run(cmd, check=True)


def safe_relative(folder, name):
    p = PurePosixPath(folder)
    if not folder.startswith('/fs/') or not p.is_absolute():
        raise ValueError(f'unexpected path: {folder!r}')
    parts = list(p.parts[1:]) + [name]
    if any(x in ('', '.', '..') or '/' in x or '\\' in x or '\x00' in x for x in parts):
        raise ValueError(f'unsafe filename/path: {folder!r}/{name!r}')
    return Path(*parts)


def parse_metadata(data):
    if not (data.startswith(b'\x00\x0e\x00\x00\x00DIVA_METADATA\x00') or
            b'DIVA_METADATA\x00' in data[:32]):
        raise ValueError('not a DIVA_METADATA record')
    paths = re.findall(rb'/fs/[\x20-\x7e]+?(?=\x00)', data)
    names = re.findall(rb'[A-Za-z0-9][A-Za-z0-9_.+ -]{0,200}\.mxf(?=\x00)', data, re.I)
    if len(paths) != 1 or len(names) != 1:
        raise ValueError(f'ambiguous source path or filename (paths={len(paths)}, names={len(names)})')
    return paths[0].decode('utf-8', 'strict'), names[0].decode('utf-8', 'strict')


def ensure_placeholder(root, relative):
    current = root
    if current.is_symlink():
        raise ValueError(f'symlink root: {current}')
    for p in relative.parts[:-1]:
        current /= p
        if current.is_symlink():
            raise ValueError(f'symlink directory: {current}')
        current.mkdir(exist_ok=True)
    target = root / relative
    if target.is_symlink():
        raise ValueError(f'symlink placeholder: {target}')
    if not target.exists():
        with target.open('xb'):
            pass
    elif not target.is_file():
        raise ValueError(f'placeholder path not regular file: {target}')
    return target


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--tape', default='/dev/nst0')
    ap.add_argument('--barcode', required=True)
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--max-objects', type=int, default=200)
    ap.add_argument('--start-file', type=int, default=None, help='explicit metadata tape-file (1,4,7,...); disables automatic resume')
    ap.add_argument('--read-bytes', type=int, default=1048576)
    args = ap.parse_args()
    if args.max_objects < 1 or args.read_bytes < 4096 or args.read_bytes > 16777215:
        ap.error('invalid limits')
    args.out.mkdir(parents=True, exist_ok=True)
    root = args.out / 'X'
    root.mkdir(exist_ok=True)
    conn = sqlite3.connect(args.out / 'catalog.sqlite3')
    conn.executescript(SCHEMA)
    last = conn.execute('SELECT MAX(metadata_file) FROM objects WHERE tape_barcode=?',
                        (args.barcode,)).fetchone()[0]
    first = args.start_file if args.start_file is not None else ((last + 3) if last is not None else 1)
    if first < 1 or (first - 1) % 3:
        ap.error('metadata tape file must be 1,4,7,...')
    print(f'Start metadata tape-file {first}; prior last={last}; no tape writes', flush=True)
    # Do not attempt to unload, load, or change media; user must verify loaded barcode.
    try:
        run_mt(args.tape, 'rewind')
        run_mt(args.tape, 'fsf', first)
        for _ in range(args.max_objects):
            current = first
            fd = os.open(args.tape, os.O_RDONLY)
            try:
                data = os.read(fd, args.read_bytes)
            finally:
                os.close(fd)
            if not data:
                print(f'FILEMARK/EOD at tape-file {current}; stopped', flush=True)
                break
            try:
                folder, name = parse_metadata(data)
                relative = safe_relative(folder, name)
                dest = ensure_placeholder(root, relative)
            except (ValueError, OSError) as e:
                print(f'STOP at tape-file {current}: {e}', file=sys.stderr)
                print('Position not recorded; investigate tape layout before continuing.', file=sys.stderr)
                return 2
            original = str(PurePosixPath(folder) / name)
            # Never overwrite restored status or manually entered size.
            with conn:
                conn.execute('''INSERT INTO objects
                    (tape_barcode,metadata_file,data_file,original_dir,filename,original_path,placeholder_path)
                    VALUES(?,?,?,?,?,?,?)
                    ON CONFLICT(tape_barcode,metadata_file) DO UPDATE SET
                      data_file=excluded.data_file,
                      original_dir=excluded.original_dir,
                      filename=excluded.filename,
                      original_path=excluded.original_path,
                      placeholder_path=excluded.placeholder_path''',
                    (args.barcode, current, current + 1, folder, name, original, str(dest)))
            print(f'metadata={current} data={current+1}: {original}', flush=True)
            first += 3
            # From metadata block 0, fsf 3 goes to the next metadata tape-file.
            run_mt(args.tape, 'fsf', 3)
        else:
            print(f'Reached --max-objects={args.max_objects}; rerun to resume', flush=True)
    except (subprocess.CalledProcessError, OSError) as e:
        print(f'STOP at/after metadata tape-file {first}: {e}', file=sys.stderr)
        print('Last successfully indexed object remains committed.', file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 0

if __name__ == '__main__':
    sys.exit(main())
