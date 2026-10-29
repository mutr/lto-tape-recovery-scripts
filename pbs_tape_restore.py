#!/usr/bin/env python3
"""Experimental offline PBS recovery from raw images or directly from LTO.

--tape physically reads the drive, spooling ONE tape file at a time to scratch.
Tape is READ ONLY; no tape-writing commands are issued. --raw uses existing images.
Omit --last-file to scan until EOD using persistent Linux st reads (no rewinds per file).
Requires pxar for snapshot extraction. Does not use PBS APIs.
"""
import argparse
import hashlib
import json
import os
import re
import pwd
import grp
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HEADER_MAGIC = bytes.fromhex('dcbdafcaeba0a528')
CHUNK_MAGIC = bytes.fromhex('6d31636dd70283bf')
SNAPSHOT_MAGIC = bytes.fromhex('da1615d011e29a62')
BLOCK = 262144
MAX_BLOB = 20 * 1024 * 1024
BLOB_MAGICS = {bytes.fromhex(x) for x in (
    '42ab3807be8370a1','31b958426fb6a37f',
    '7b6783be222d4cf0','e6591bbf0bbfd80b')}


CONTENT_MAGIC = bytes.fromhex('63ee149fcdf29b0c')


def unpack_tape_blocks(source, target):
    """Decode fixed 256-KiB PBS tape blocks into the logical payload stream."""
    if source.stat().st_size % BLOCK:
        raise ValueError(f'Raw tape file is not a multiple of 256 KiB: {source}')
    with source.open('rb') as src, target.open('wb') as dst:
        seq = 0
        ended = False
        for offset in range(0, source.stat().st_size, BLOCK):
            frame = src.read(BLOCK)
            if len(frame) != BLOCK or frame[:8] != HEADER_MAGIC:
                raise ValueError(f'Invalid tape block header at {source}:{offset}')
            flags = frame[8]
            used = int.from_bytes(frame[9:12], 'little')
            number = struct.unpack_from('<I', frame, 12)[0]
            if number != seq or used > BLOCK - 16 or (used == 0 and not flags & 1):
                raise ValueError(f'Bad tape block seq/payload at {source}:{offset}')
            if ended:
                raise ValueError(f'Data after end of stream in {source}')
            dst.write(frame[16:16+used])
            seq += 1
            if flags & 1:
                ended = True
                if flags & 2:
                    raise ValueError(f'Incomplete multivolume stream: {source}')
        if not ended:
            raise ValueError(f'Missing end-of-stream marker in {source}')


def read_header(f):
    b = f.read(48)
    if len(b) != 48 or b[:8] != CONTENT_MAGIC:
        raise ValueError('Unknown PBS MediaContentHeader')
    size = struct.unpack_from('<I', b, 40)[0]
    if size > 65536:
        raise ValueError('Unreasonable JSON header length')
    raw = f.read(size)
    try:
        data = json.loads(raw)
    except Exception as ex:
        raise ValueError(f'Invalid media header JSON: {ex}') from ex
    return b[8:16], data


def safe_snapshot_path(s):
    if not isinstance(s, str) or not re.fullmatch(r'(ct|vm|host)/[A-Za-z0-9_.-]+/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', s):
        raise ValueError(f'Unsafe/unsupported snapshot path: {s!r}')
    return Path(*s.split('/'))


def entries(folder):
    paths = sorted(folder.glob('file-??????.bin'))
    if not paths:
        raise ValueError('No file-XXXXXX.bin found')
    for p in paths:
        with tempfile.TemporaryDirectory(prefix='pbs-tape-unframed-') as tmp:
            unpacked = Path(tmp) / 'payload.bin'
            unpack_tape_blocks(p, unpacked)
            with unpacked.open('rb') as f:
                kind, meta = read_header(f)
            yield p, unpacked, kind, meta


def chunk_entries(f, size):
    """Yield raw stored blobs. Detect entry magic from first well-formed entry.

    Unknown padding or truncation is an error: never silently shift boundaries.
    """
    magic = None
    offset = f.tell()
    count = 0
    while offset + 48 <= size:
        f.seek(offset)
        head = f.read(48)
        if not any(head):
            # Tape padding after final entry may consist solely of zero bytes.
            if any(f.read()):
                raise ValueError(f'Non-zero bytes after zero padding at {offset}')
            break
        entry_magic, digest, blob_size = head[:8], head[8:40], struct.unpack_from('<Q', head, 40)[0]
        if magic is None:
            magic = entry_magic
        if entry_magic != magic:
            raise ValueError(f'Unexpected chunk entry magic at offset {offset}')
        if not 12 <= blob_size <= MAX_BLOB:
            raise ValueError(f'Invalid blob size {blob_size} at {offset}')
        if offset + 48 + blob_size > size:
            raise ValueError(f'Truncated chunk at offset {offset}')
        blob = f.read(blob_size)
        if blob[:8] not in BLOB_MAGICS:
            raise ValueError(f'Unknown DataBlob magic at offset {offset}')
        # Preserve DataBlob verbatim. Integrity/hash verification is delegated to PBS verify.
        yield digest.hex(), blob
        count += 1
        offset += 48 + blob_size
    if count == 0:
        raise ValueError('No chunk entries found (or image contains only padding)')


OWNER = None


def create_group_owner(datastore, relative_snapshot, backup_owner):
    """Create PBS group ownership metadata, never replace an existing owner."""
    group = datastore / relative_snapshot.parent
    group.mkdir(parents=True, exist_ok=True)
    if OWNER:
        os.chown(group, *OWNER)
        os.chmod(group, 0o750)
    install_noreplace(group / 'owner', (backup_owner + '\n').encode())


def install_noreplace(path, data):
    created_dirs = []
    parent = path.parent
    while not parent.exists():
        created_dirs.append(parent)
        parent = parent.parent
    path.parent.mkdir(parents=True, exist_ok=True)
    if OWNER:
        for directory in reversed(created_dirs):
            os.chown(directory, *OWNER)
    if path.exists():
        if path.read_bytes() != data:
            raise RuntimeError(f'Existing file differs: {path}')
        return False
    fd, temp = tempfile.mkstemp(prefix='.pbs-rescue-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        try:
            os.link(temp, path)  # atomic, fails if destination exists
            if OWNER:
                os.chown(path, *OWNER)
            return True
        except FileExistsError:
            if path.read_bytes() != data:
                raise RuntimeError(f'Concurrent write conflict: {path}')
            return False
    finally:
        os.unlink(temp)


def extract_snapshot(path, target):
    if not shutil.which('pxar'):
        raise RuntimeError('pxar command not installed. Install PBS pxar tool.')
    # Expose the archive payload without making a second giant file.
    # POSIX proc fd points at file offset only for the current process; use a temp
    # file as pxar expects a seekable archive for reliable extraction.
    with tempfile.TemporaryDirectory(prefix='pbs-tape-snapshot-') as t:
        archive = Path(t) / 'snapshot.pxar'
        with path.open('rb') as src, archive.open('wb') as dst:
            read_header(src)
            shutil.copyfileobj(src, dst, 4 * 1024 * 1024)
        stage = Path(t) / 'snapshot'
        stage.mkdir()
        subprocess.run(['pxar', 'extract', str(archive), str(stage)], check=True)
        found = list(stage.iterdir())
        if not found:
            raise RuntimeError('No snapshot files extracted')
        if target.exists() and any(target.iterdir()):
            raise RuntimeError(f'Snapshot target is not empty: {target}')
        target.mkdir(parents=True, exist_ok=True)
        if OWNER:
            os.chown(target, *OWNER)
            os.chown(target.parent, *OWNER)
        for item in found:
            if item.is_symlink() or not item.is_file():
                raise RuntimeError(f'Unexpected extracted entry {item}')
            install_noreplace(target / item.name, item.read_bytes())


def mt(device, *args):
    subprocess.run(['mt', '-f', device, *map(str, args)], check=True)


def barcode_in_changer(changer, barcode):
    result = subprocess.run(['mtx', '-f', changer, 'status'], capture_output=True,
                            text=True, check=True)
    line = next((line for line in result.stdout.splitlines()
                 if line.startswith('Data Transfer Element 0:')), '')
    if not line or not re.search(r'VolumeTag\s*=\s*' + re.escape(barcode) + r'\s*$', line):
        raise RuntimeError('Wrong tape in drive: ' + (line or 'drive not loaded'))


def capture_tape_file(device, dest, limit):
    # Mirrors the tested pbs_tape_rescue.py acquisition loop; exact tape-file
    # boundaries preserved. Nothing is ever written to the tape device.
    total = 0
    with open(device, 'rb', buffering=0) as tape, dest.open('xb', buffering=0) as out:
        while True:
            block = tape.read(8 * 1024 * 1024)
            if not block:  # tape filemark
                break
            total += len(block)
            if total > limit:
                raise RuntimeError(f'Tape file exceeds configured maximum ({limit} bytes)')
            out.write(block)
    return total



def capture_next_tape_file(tape, dest, limit):
    """Read one physical tape file from a persistent Linux st descriptor.

    The first zero read after data ends the tape file. At EOD, the first
    zero read ends the previous file and the second zero read (with no data)
    signals EOD. An unexpected EIO, including on blank media, is NOT
    interpreted as successful recovery: it remains a hard error.
    """
    total = 0
    with dest.open('xb', buffering=0) as out:
        while True:
            data = tape.read(8 * 1024 * 1024)
            if not data:
                break
            total += len(data)
            if total > limit:
                raise RuntimeError(f'Tape file exceeds configured maximum ({limit} bytes)')
            out.write(data)
    return total

def process_image(path, a, discovered=None):
    chunks = snapshots = 0
    with tempfile.TemporaryDirectory(prefix='pbs-tape-unframed-', dir=a.scratch) as tmp:
        payload = Path(tmp) / 'payload.bin'
        unpack_tape_blocks(path, payload)
        with payload.open('rb') as f:
            kind, meta = read_header(f)
        print(f'{path.name}: {meta} magic={kind.hex()}', flush=True)
        if discovered is not None:
            store = meta.get('store')
            if kind in (CHUNK_MAGIC, SNAPSHOT_MAGIC) and isinstance(store, str) and store:
                record = discovered.setdefault(store, {'chunk_archives': 0, 'snapshots': []})
                if kind == CHUNK_MAGIC:
                    record['chunk_archives'] += 1
                else:
                    record['snapshots'].append(meta.get('snapshot', '?'))
            return chunks, snapshots
        if kind not in (CHUNK_MAGIC, SNAPSHOT_MAGIC):
            return chunks, snapshots
        if meta.get('store') != a.source_store:
            print('  skipping other store')
            return chunks, snapshots
        if kind == CHUNK_MAGIC:
            with payload.open('rb') as f:
                read_header(f)
                for digest, blob in chunk_entries(f, payload.stat().st_size):
                    chunks += 1
                    if a.restore:
                        target = a.datastore_path / '.chunks' / digest[:4] / digest
                        install_noreplace(target, blob)
            print('  chunk archive parsed', flush=True)
        else:
            rel = safe_snapshot_path(meta['snapshot'])
            snapshots += 1
            if a.restore:
                extract_snapshot(payload, a.datastore_path / rel)
                create_group_owner(a.datastore_path, rel, a.backup_owner)
            print(f'  snapshot: {rel}', flush=True)
    return chunks, snapshots


def verify_manifest(folder):
    manifest = folder / 'manifest.json'
    if not manifest.exists():
        return
    m = json.loads(manifest.read_text())
    for n, rec in m.get('files', {}).items():
        item = folder / f'file-{int(n):06d}.bin'
        if item.exists():
            h = hashlib.sha256()
            with item.open('rb') as f:
                for block in iter(lambda: f.read(4 * 1024 * 1024), b''):
                    h.update(block)
            if h.hexdigest() != rec['sha256'] or item.stat().st_size != rec['size_bytes']:
                raise RuntimeError(f'Manifest verification failed: {item}')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument('--raw', type=Path, help='Directory with saved file-XXXXXX.bin')
    source.add_argument('--tape', help='Non-rewinding tape device, e.g. /dev/nst0')
    p.add_argument('--changer', default='/dev/sg3')
    p.add_argument('--barcode', help='Required with --tape: must match loaded media')
    p.add_argument('--first-file', type=int, default=0)
    p.add_argument('--last-file', type=int, help='Optional inclusive last tape-file index; if omitted, read until Linux st reports end-of-data')
    p.add_argument('--max-gib', type=float, default=64,
                   help='Maximum physical tape-file size (default 64 GiB)')
    p.add_argument('--scratch', type=Path, help='Scratch disk for one tape file + decoded payload + pxar')
    p.add_argument('--datastore-path', type=Path)
    p.add_argument('--restore', action='store_true', help='Write to datastore (otherwise probe only)')
    p.add_argument('--source-store', help='Source store recorded in tape archive headers')
    p.add_argument('--list-stores', action='store_true', help='Inspect tape headers and list source datastores without restoring')
    p.add_argument('--owner', default='backup')
    p.add_argument('--backup-owner', default='root@pam')
    a = p.parse_args()
    global OWNER

    if a.tape:
        if not a.barcode or not re.fullmatch(r'[A-Za-z0-9_-]{3,32}', a.barcode):
            p.error('--tape requires a valid --barcode')
        if a.first_file < 0 or (a.last_file is not None and a.last_file < a.first_file):
            p.error('Require --first-file >= 0 and optional --last-file >= --first-file')
        if not a.tape.startswith('/dev/nst'):
            p.error('Use non-rewinding tape device /dev/nstN')
        if not shutil.which('mt') or not shutil.which('mtx'):
            p.error('Install mt-st and mtx for tape mode')
        if a.max_gib <= 0:
            p.error('--max-gib must be positive')
    if a.tape and not a.scratch:
        p.error('Tape mode requires --scratch (a temporary disk directory)')
    if a.scratch:
        a.scratch = a.scratch.resolve()
        if not a.scratch.is_dir():
            p.error('--scratch must exist as a directory')
    if a.list_stores and a.restore:
        p.error('--list-stores cannot be used with --restore')
    if a.restore and not a.source_store:
        p.error('--restore requires --source-store; use --list-stores to discover names')
    if not a.list_stores and not a.source_store:
        p.error('Specify --source-store or --list-stores')
    if a.restore:
        OWNER = (pwd.getpwnam(a.owner).pw_uid, grp.getgrnam(a.owner).gr_gid)
        if not re.fullmatch(r'[A-Za-z0-9_.@-]+', a.backup_owner):
            p.error('Invalid PBS backup owner identifier')
        if not a.datastore_path or not a.datastore_path.is_dir() or not (a.datastore_path / '.chunks').is_dir():
            p.error('Target must be an initialized PBS datastore containing .chunks')
        a.datastore_path = a.datastore_path.resolve()
        if a.raw and (a.raw.resolve() == a.datastore_path or a.raw.resolve().is_relative_to(a.datastore_path)):
            p.error('Raw input must not reside inside target datastore')
        if a.scratch and (a.scratch == a.datastore_path or a.scratch.is_relative_to(a.datastore_path)):
            p.error('Scratch must not reside inside target datastore')
    chunks = snapshots = 0
    discovered = {} if a.list_stores else None
    if a.raw:
        verify_manifest(a.raw)
        paths = sorted(a.raw.glob('file-??????.bin'))
        if not paths:
            p.error('No raw tape files found')
        for path in paths:
            c, s = process_image(path, a, discovered)
            chunks += c
            snapshots += s
    else:
        barcode_in_changer(a.changer, a.barcode)
        if a.last_file is None:
            print(f'PHYSICAL LTO READ ONLY: {a.barcode}, from tape file {a.first_file} until EOD', flush=True)
            print('A single zero-length read is a FILEMARK; two consecutive zero-length reads signal EOD.', flush=True)
            # A single open non-rewinding descriptor is essential for st's
            # filemark/EOD semantics; reopening or seeking after each file
            # can discard the EOF state and skip positions.
            mt(a.tape, 'rewind')
            if a.first_file:
                mt(a.tape, 'fsf', a.first_file)
            with open(a.tape, 'rb', buffering=0) as tape:
                number = a.first_file
                while True:
                    barcode_in_changer(a.changer, a.barcode)
                    with tempfile.TemporaryDirectory(prefix='pbs-tape-live-', dir=a.scratch) as temp:
                        path = Path(temp) / f'file-{number:06d}.bin'
                        length = capture_next_tape_file(tape, path, int(a.max_gib * 1024**3))
                        if length == 0:
                            print(f'[{number}] EOD confirmed: two consecutive zero-byte reads (no tape file)', flush=True)
                            break
                        print(f'[{number}] read {length:,} bytes from {a.tape}', flush=True)
                        c, s = process_image(path, a, discovered)
                        chunks += c
                        snapshots += s
                    number += 1
        else:
            print(f'PHYSICAL LTO READ ONLY: {a.barcode}, files {a.first_file}..{a.last_file}', flush=True)
            print('Tape files are temporarily buffered ONE AT A TIME (not all retained).', flush=True)
            for number in range(a.first_file, a.last_file + 1):
                barcode_in_changer(a.changer, a.barcode)
                print(f'[{number}] rewind + fsf {number}', flush=True)
                mt(a.tape, 'rewind')
                if number:
                    mt(a.tape, 'fsf', number)
                with tempfile.TemporaryDirectory(prefix='pbs-tape-live-', dir=a.scratch) as temp:
                    path = Path(temp) / f'file-{number:06d}.bin'
                    length = capture_tape_file(a.tape, path, int(a.max_gib * 1024**3))
                    print(f'[{number}] read {length:,} bytes from {a.tape}', flush=True)
                    if length == 0:
                        raise RuntimeError(f'Unexpected empty tape file {number} before --last-file {a.last_file}')
                    c, s = process_image(path, a, discovered)
                    chunks += c
                    snapshots += s
    if discovered is not None:
        print('=== SOURCE DATASTORES FOUND ===')
        if not discovered:
            print('No PBS datastore archives found in the scanned tape files.')
        for store, record in sorted(discovered.items()):
            print(f'{store}: {record["chunk_archives"]} chunk archive(s), {len(record["snapshots"])} snapshot(s)')
            for snapshot in record['snapshots']:
                print(f'  {snapshot}')
        return
    print(f'Finished: {chunks} chunk entries; {snapshots} snapshots; restore={a.restore}')
    if not a.restore:
        print('No datastore writes; use --restore after probing.')
    else:
        print('Experimental recovery: run PBS verify on all restored snapshots.')

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as e:
        sys.exit(f'ERROR: {e}')
