#!/usr/bin/env python3
"""Restore one indexed Yosemite object using variable first DATU prefix and OEND size.

Uses v2.3 catalog.sqlite3 record offsets. Never writes to the tape.
The source tape must be the same cartridge and record layout as the index.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import stat
import hashlib
import zipfile
import re

BLOCK = 65536

def load_parser(path):
    spec = importlib.util.spec_from_file_location('yosemite_parser_23', str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class Reader:
    def __init__(self, tape, input_file, initial_block):
        self.fd = None
        self.file = None
        self.buffer = bytearray()
        self.position = initial_block * BLOCK
        if tape:
            subprocess.run(['mt', '-f', tape, 'rewind'], check=True)
            # SCSI SPACE(6) uses a signed 24-bit record count. Split large
            # record skips rather than issuing an out-of-range MTFSR command.
            # A filemark or I/O error must abort: do not infer a position.
            remaining = initial_block
            while remaining:
                step = min(remaining, 1_000_000)
                subprocess.run(['mt', '-f', tape, 'fsr', str(step)], check=True)
                remaining -= step
            self.fd = os.open(tape, os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0))
        else:
            self.file = input_file.open('rb')
            self.file.seek(self.position)
    def close(self):
        if self.fd is not None: os.close(self.fd)
        if self.file is not None: self.file.close()
    def read(self, n):
        while len(self.buffer) < n:
            if self.fd is not None:
                chunk = os.read(self.fd, BLOCK)
                if chunk and len(chunk) != BLOCK:
                    raise IOError(f'Unexpected physical record size {len(chunk)}')
            else:
                chunk = self.file.read(BLOCK)
            if not chunk:
                raise EOFError(f'filemark/EOD or capture end at {self.position + len(self.buffer)}')
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:n]); del self.buffer[:n]
        self.position += n
        return result
    def skip(self, n):
        while n:
            k = min(n, 1024 * 1024)
            self.read(k)
            n -= k


from contextlib import nullcontext as _no_temp

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--db', type=Path, required=True, help='v2.3 catalog.sqlite3')
    ap.add_argument('--path', help='exact original_path in catalog')
    ap.add_argument('--seq', type=int, help='begin_seq (use if names duplicate)')
    ap.add_argument('--tape', default='/dev/nst0')
    ap.add_argument('--input', type=Path, help='read from capture instead of tape')
    ap.add_argument('--out', type=Path, help='NEW destination; if omitted, replace catalog placeholder after validation')
    ap.add_argument('--parser', type=Path, default=Path('/root/tape-recovery/yosemite_recover_v2_3.py'))
    ap.add_argument('--repair-restored', action='store_true', help='EXPLICITLY replace a v3-restored (possibly corrupt) file after validation; backs up old contents')
    ap.add_argument('--changer', default='/dev/sg3', help='SCSI changer for mandatory tape volume-tag check')
    ap.add_argument('--list', action='store_true', help='search catalog by substring without reading tape')
    args = ap.parse_args()
    db = sqlite3.connect(f'file:{args.db.resolve()}?mode=ro', uri=True)
    if args.list:
        for row in db.execute('SELECT begin_seq,size,original_path,status FROM objects WHERE kind="file" AND original_path LIKE ? ORDER BY original_path LIMIT 100',('%'+(args.path or '')+'%',)):
            print(f'{row[0]:>9} {row[1]:>13} {row[3]:<16} {row[2]}')
        return
    if (args.path is None) == (args.seq is None): ap.error('pass exactly one of --path or --seq')
    inplace = args.out is None
    if not inplace and args.out.resolve() == args.db.parent.resolve(): ap.error('do not use --out for catalog; omit --out for safe placeholder replacement')
    if args.seq is not None:
        rows = db.execute('SELECT begin_seq,end_seq,kind,original_path,size,begin_offset,end_offset,source,status FROM objects WHERE begin_seq=?',(args.seq,)).fetchall()
    else:
        rows = db.execute('SELECT begin_seq,end_seq,kind,original_path,size,begin_offset,end_offset,source,status FROM objects WHERE original_path=? AND kind="file"',(args.path,)).fetchall()
    if not rows: raise ValueError('file not found in index')
    if len(rows) != 1:
        for row in rows: print(f'seq={row[0]} size={row[4]} path={row[3]}')
        raise ValueError('multiple matches; specify --seq')
    seq, end_seq, kind, orig, expected, start, end, source, status = rows[0]
    if kind != 'file': raise ValueError(f'object is {kind}, not file')
    if status not in ('placeholder','name_conflict','restored'):
        raise ValueError(f'unexpected status={status}; check catalog before proceeding')
    records = db.execute('SELECT seq,byte_offset,kind,flag,payload_size,logical FROM records WHERE object_begin_seq=? ORDER BY byte_offset',(seq,)).fetchall()
    if not records or records[0][0] != seq or records[0][2] != 'OBGN' or records[-1][0] != end_seq or records[-1][2] != 'OEND':
        raise ValueError('incomplete/corrupt record index')
    if records[0][1] != start or records[-1][1] != end:
        raise ValueError('object offsets mismatch')
    if args.input is None and source != args.tape:
        raise ValueError(f'catalog source is {source!r}; requested device is {args.tape!r}')
    if args.input is not None and not args.input.is_file():
        raise ValueError('missing input capture')
    placeholder = None
    if inplace:
        if status != 'placeholder' and not (status == 'restored' and args.repair_restored):
            raise ValueError(f'cannot replace catalog entry with status={status}; use --out or explicit --repair-restored')
        if expected == 0:
            raise ValueError('zero-byte object already has correct placeholder; no tape extraction necessary')
        relrow = db.execute('SELECT relative_path FROM objects WHERE begin_seq=?',(seq,)).fetchone()
        if not relrow or not relrow[0]: raise ValueError('missing relative_path')
        rel = Path(relrow[0])
        if rel.is_absolute() or '..' in rel.parts or not rel.parts:
            raise ValueError('unsafe relative_path')
        placeholder = args.db.parent / rel
        catalog_root = args.db.parent.resolve()
        if placeholder.parent.resolve() != catalog_root / rel.parent:
            raise ValueError('symlink in catalog path')
        st = placeholder.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or (st.st_size != 0 if status=='placeholder' else st.st_size != expected):
            raise ValueError('target file size/type changed; refusing to overwrite')
    elif args.out.exists() and any(args.out.iterdir()):
        raise FileExistsError(f'output must be empty to prevent collisions: {args.out}')
    print(f'Selected seq={seq} size={expected} ({expected/1024**2:.2f} MiB) path={orig}',flush=True)
    print(f'Tape range: physical blocks {start//BLOCK}..{end//BLOCK}; records={len(records)}',flush=True)
    parser = load_parser(args.parser)
    if args.input is None:
        # This is essential: indexes of different cartridges have unrelated offsets.
        label = args.db.parent.parent.name
        if not re.fullmatch(r'[A-Za-z0-9_-]+L[456789]', label):
            raise ValueError(f'cannot infer expected cartridge VolumeTag from {args.db}; use --input for offline test')
        result=subprocess.run(['mtx','-f',args.changer,'status'],check=True,text=True,capture_output=True)
        loaded=re.search(r'Data Transfer Element 0:Full[^\n]*VolumeTag\s*=\s*([^\s]+)',result.stdout)
        if not loaded or loaded.group(1)!=label:
            raise ValueError(f'wrong cartridge or unavailable VolumeTag: expected {label}, loaded {loaded.group(1) if loaded else "UNKNOWN"}; no positioning attempted')
    # Only stage on a normal filesystem, never in the indexed placeholder itself.
    with tempfile.TemporaryDirectory(prefix='.yosemite-selected-',dir=str(args.db.parent if inplace else args.out.parent)) if inplace else _no_temp() as scratch:
        destination = Path(scratch) if inplace else args.out
        destination.mkdir(parents=True,exist_ok=True)
        if not inplace and any(destination.iterdir()):
            raise FileExistsError('output directory must be empty')
        output_file=destination/'payload.bin'
        reader=Reader(None if args.input else args.tape,args.input,start//BLOCK)
        prefix=None
        first=True
        have_meta=False
        running_logical=0
        actual_bytes=0
        trailing_bytes=0
        end_size=None
        digest=hashlib.sha256()
        try:
            reader.skip(start%BLOCK)
            with output_file.open('xb') as f:
                for rseq,offset,rkind,flag,size,logical in records:
                    if reader.position!=offset:
                        raise IOError(f'offset mismatch: expected {offset}, got {reader.position}')
                    h=reader.read(64)
                    record=parser.parse_header(h)
                    if record is None or (record['seq'],record['kind'],record['flag'],record['size'],record['logical']) != (rseq,rkind,flag,size,logical):
                        raise IOError(f'tape/header differs from catalog at seq={rseq}, byte={offset}')
                    payload=reader.read(((size+63)//64)*64)[:size]
                    if rkind=='DATU' and flag==0:
                        if have_meta: raise IOError('duplicate metadata DATU')
                        have_meta=True
                        items=parser.extract_path(payload)
                        if not items or items[-1][0]!=3:
                            raise IOError('invalid file pathname metadata')
                        if '/'.join(x[1] for x in items)!=orig:
                            raise IOError('original path on tape differs from SQLite')
                    elif rkind=='DATU' and flag==1:
                        if not have_meta: raise IOError('data before metadata')
                        if first:
                            first=False
                            if logical!=0 or len(payload)<12:
                                raise IOError('invalid first DATU')
                            if len(payload)==220 and payload[:12]==bytes.fromhex('0300000002000000c8000000'):
                                if expected!=0: raise IOError('ACL-only DATU for nonempty file')
                                prefix=220
                                continue
                            if payload[:8]!=bytes.fromhex('0300000002000000'):
                                raise IOError('unknown first DATU prefix signature')
                            prefix=int.from_bytes(payload[8:12],'little')+40
                            if prefix<40 or prefix>len(payload) or prefix>1024*1024:
                                raise IOError(f'invalid DATU prefix: {prefix} / {len(payload)}')
                            chunk=payload[prefix:]
                        else:
                            if logical!=running_logical:
                                raise IOError(f'DATU logical offset {logical} != {running_logical}')
                            chunk=payload
                        running_logical+=size
                        # Do not finalize until OEND, which determines actual file length.
                        f.write(chunk)
                        actual_bytes+=len(chunk)
                    elif rkind=='OEND':
                        end_size=logical
                        if end_size!=expected:
                            raise IOError(f'OEND size={end_size}, catalog={expected}')
                if not have_meta or first or end_size is None:
                    raise IOError('incomplete object')
                if actual_bytes<expected:
                    raise IOError(f'not enough data: {actual_bytes}, expected={expected}')
                trailing_bytes=actual_bytes-expected
                if trailing_bytes>4096:
                    raise IOError(f'unexpected DATU trailing bytes: {trailing_bytes}')
                f.truncate(expected)
                f.flush(); os.fsync(f.fileno())
        finally:
            reader.close()
        if output_file.stat().st_size!=expected:
            raise IOError('staged file size differs from catalog')
        # For ZIP-based formats validate all member CRCs, not only central-directory presence.
        suffix=Path(orig).suffix.lower()
        if suffix in ('.docx','.xlsx','.pptx','.zip','.jar','.odt','.ods','.odp'):
            if not zipfile.is_zipfile(output_file):
                raise IOError(f'{suffix} is not a valid ZIP container; NOT replacing target')
            with zipfile.ZipFile(output_file) as z:
                invalid=z.testzip()
                if invalid is not None: raise IOError(f'ZIP CRC mismatch in {invalid}')
                if suffix=='.docx' and 'word/document.xml' not in z.namelist():
                    raise IOError('DOCX missing word/document.xml')
                if suffix=='.xlsx' and 'xl/workbook.xml' not in z.namelist():
                    raise IOError('XLSX missing xl/workbook.xml')
                if suffix=='.pptx' and 'ppt/presentation.xml' not in z.namelist():
                    raise IOError('PPTX missing ppt/presentation.xml')
        with output_file.open('rb') as f:
            for buf in iter(lambda:f.read(4*1024*1024),b''): digest.update(buf)
        sha=digest.hexdigest()
        if inplace:
            st=placeholder.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or (st.st_size!=0 if status=='placeholder' else st.st_size!=expected):
                raise ValueError('target changed while restoring; refusing replacement')
            backup=None
            if status=='restored':
                backup=placeholder.with_name(placeholder.name+f'.yosemite-v3-bad-{seq}.bak')
                if backup.exists() or backup.is_symlink():
                    raise FileExistsError(f'backup exists: {backup}')
                # Keep the prior bytes as a forensic backup before replacement.
                import shutil
                shutil.copy2(placeholder,backup)
            os.replace(output_file,placeholder)
            db.close()
            wdb=sqlite3.connect(str(args.db))
            try:
                wdb.execute('BEGIN IMMEDIATE')
                row=wdb.execute('SELECT status,relative_path FROM objects WHERE begin_seq=?',(seq,)).fetchone()
                if row!=(status,rel.as_posix()):
                    raise ValueError('catalog row changed during restoration')
                wdb.execute('UPDATE objects SET status=? WHERE begin_seq=?',('restored',seq))
                wdb.commit()
            finally:
                wdb.close()
            print(f'RESTORED IN PLACE: {placeholder}')
            if backup: print(f'PREVIOUS CONTENT BACKUP: {backup}')
        else:
            parts=[parser.safe_part(name,volume=i==0) for i,(_,name) in enumerate(items)]
            parent=parser.safe_mkdir_tree(destination,parts[:-1])
            target=parent/parts[-1]
            if target.exists() or target.is_symlink(): raise FileExistsError(target)
            os.replace(output_file,target)
            print(f'RESTORED: {target}')
        print(f'PREFIX: {prefix} bytes; TRAILER: {trailing_bytes} bytes')
        print(f'SIZE: {expected} bytes\nSHA256: {sha}')
        if suffix not in ('.docx','.xlsx','.pptx','.zip','.jar','.odt','.ods','.odp'):
            print('NOTE: no independent format-specific integrity validation available')


if __name__ == '__main__':
    try: main()
    except (ValueError,OSError,sqlite3.Error,EOFError,subprocess.CalledProcessError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(2)
