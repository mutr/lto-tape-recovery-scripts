#!/usr/bin/env python3
"""Experimental read-only recovery of Yosemite F700/OHDR backup objects.

A capture may begin mid-object. Tape mode reads fixed 65536-byte physical records
from /dev/nst0 (device is NEVER opened for writing). This parser is based on a
small observed sample; retain original media and audit recovered data.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import struct
import subprocess
import sys
import time

HEADER=64
BLOCK=65536
MAX_DATA=16*1024*1024
MAGIC=b'F700'
ANCHOR=b'Yosemite Server Backup Storage Domain\x00'
PATH_MARKER=re.compile(rb'([\x01\x02\x03])\x06\x00\x00([\x01\x05])\x00\x00\x00')


def u32(buf,off): return struct.unpack_from('<I',buf,off)[0]

def parse_header(buf,at=0):
    if len(buf)-at<HEADER or buf[at:at+4]!=MAGIC: return None
    h=buf[at:at+HEADER]
    if h[8:12]!=b'OHDR' or h[16:20] not in (b'OBGN',b'OEND',b'DATU'): return None
    size=u32(h,0x24)
    if size>MAX_DATA or size!=u32(h,0x28): return None
    if h[16:20]!=b'DATU' and size: return None
    if h[16:20]==b'DATU' and u32(h,0x14) not in (0,1): return None
    return {'seq':u32(h,4),'kind':h[16:20].decode(), 'flag':u32(h,0x14),
            'size':size,'logical':u32(h,0x2c)}


def extract_path(meta):
    anchor=meta.find(ANCHOR)
    if anchor<0: return None
    items=[]
    for m in PATH_MARKER.finditer(meta,anchor+len(ANCHOR)):
        start=m.end(); end=meta.find(b'\0',start)
        if end<0 or not 0<end-start<=512: continue
        try: name=meta[start:end].decode('utf-8','strict')
        except UnicodeError: continue
        if not name or any(ord(ch)<32 for ch in name): continue
        items.append((m.group(1)[0],name))
    # Require one named volume and final entry type to be file/dir.
    if not items or items[0][0]!=1 or items[-1][0] not in (2,3): return None
    return items


def short_name(meta,seq):
    # Offset 0x28 is UTF-16LE length for the sampled short-name variant.
    fallback=f'object-{seq:08d}.bin'
    if len(meta)<0x30: return fallback
    n=u32(meta,0x28)
    if n>=2 and n<=1024 and n%2==0 and 0x2c+n<=len(meta):
        try:
            name=meta[0x2c:0x2c+n].decode('utf-16le').rstrip('\0')
            if name and all(ch.isprintable() for ch in name): return name
        except UnicodeError: pass
    return fallback


def safe_part(name, volume=False):
    # Avoid path traversal, NUL, reserved path separators and control chars.
    if volume and re.fullmatch(r'[A-Za-z]:',name): return name[0].upper()
    if not name or name in ('.','..') or '/' in name or '\\' in name or '\0' in name:
        raise ValueError(f'unsafe path component: {name!r}')
    if any(ord(ch)<32 or ord(ch)==127 for ch in name): raise ValueError('control character in path')
    if len(name.encode('utf-8'))>240: raise ValueError('path component too long')
    return name


def safe_mkdir_tree(root, parts):
    current=root
    for part in parts:
        current=current/part
        if current.is_symlink(): raise ValueError(f'symlink in output path: {current}')
        if current.exists():
            if not current.is_dir(): raise ValueError(f'not a directory: {current}')
        else: current.mkdir(mode=0o700)
    return current


class Recovery:
    def __init__(self,out,emit,resume=False):
        self.out=out; self.emit=emit; self.resume=resume; self.state=None; self.prev_seq=None
        self.errors=0; self.committed=0; self.dirs=0; self.objects=0
        safe_mkdir_tree(out,[])
        safe_mkdir_tree(out,['.partial'])

    def log(self,event,**kw): self.emit(dict(event=event,**kw))

    def fail_current(self,reason):
        s=self.state
        if s is None: return
        if s['file'] is not None:
            s['file'].close()
        self.log('incomplete',begin_seq=s['seq'],name=s['name'],reason=reason,
                 temporary=str(s['tmp']) if s['tmp'] else None)
        self.errors+=1; self.state=None

    def handle(self,r,payload):
        seq=r['seq']
        if self.prev_seq is not None and seq!=(self.prev_seq+1)&0xffffffff:
            self.fail_current(f'sequence gap {self.prev_seq}->{seq}')
            self.log('sequence_gap',previous=self.prev_seq,current=seq)
        self.prev_seq=seq
        kind=r['kind']
        if kind=='OBGN':
            self.fail_current('new OBGN before OEND')
            self.objects+=1
            self.state=dict(seq=seq,name=short_name(b'',seq),items=None,metadata=False,
                            is_dir=False,data=False,total=0,file=None,tmp=None,next_logical=0,dir_aux_records=0,dir_aux_bytes=0,short_acl=None)
            self.log('begin',seq=seq)
        elif kind=='DATU':
            s=self.state
            if s is None: return
            if r['flag']==0:
                if s['data']:
                    self.fail_current('metadata after content'); return
                s['metadata']=True
                s['items']=extract_path(payload)
                s['name']=s['items'][-1][1] if s['items'] else short_name(payload,s['seq'])
                s['is_dir']=bool(s['items'] and s['items'][-1][0]==2)
                self.log('metadata',begin_seq=s['seq'],name=s['name'],
                         path='/'.join(x[1] for x in s['items']) if s['items'] else None,
                         object_type='directory' if s['is_dir'] else 'file',size=r['size'])
            else:
                if not s['metadata']:
                    self.fail_current('data before metadata'); return
                if s['is_dir']:
                    # Observed Yosemite directory objects have an auxiliary DATU
                    # even though OEND logical size is zero. Do not materialize it.
                    # Bound its size to avoid silently discarding real file data.
                    if r['size'] > 4096 or r['logical'] != 0:
                        self.fail_current(f'unexpected directory auxiliary DATU: size={r["size"]}, logical={r["logical"]}'); return
                    s['dir_aux_records'] += 1
                    s['dir_aux_bytes'] += r['size']
                    return
                if not s['data']:
                    # Observed zero-length file: a 220-byte Windows security
                    # descriptor DATU with no data bytes. Defer validation until
                    # OEND confirms that the logical file size is exactly zero.
                    if (len(payload)==220 and r['logical']==0 and
                        payload[:12]==bytes.fromhex('0300000002000000c8000000')):
                        s['short_acl']=payload
                        return
                    if s['short_acl'] is not None:
                        self.fail_current('additional content after short ACL DATU'); return
                    if len(payload)<240 or r['logical']!=0:
                        self.fail_current('invalid first data prefix or logical offset'); return
                    tmp=self.out/'.partial'/f'{s["seq"]:08d}.part'
                    if tmp.exists() or tmp.is_symlink():
                        if (self.resume and tmp.is_file() and not tmp.is_symlink()):
                            # A prior session can stop inside an object. Replay
                            # from its preceding completed-object checkpoint.
                            tmp.unlink()
                            self.log('partial_restarted',begin_seq=s['seq'],path=str(tmp))
                        else:
                            self.fail_current(f'partial already exists: {tmp}'); return
                    s['tmp']=tmp; s['file']=tmp.open('xb'); s['data']=True
                    chunk=payload[240:]
                else:
                    if r['logical']!=s['next_logical']:
                        self.fail_current(f'logical mismatch: expected {s["next_logical"]}, got {r["logical"]}')
                        return
                    chunk=payload
                s['file'].write(chunk)
                s['total']+=len(chunk)
                # Yosemite logical offset is measured in bytes of DATU, not of file.
                s['next_logical']+=r['size']
        elif kind=='OEND':
            s=self.state
            if s is None: return
            size=r['logical']
            if s['is_dir'] and size==0 and not s['data']:
                if not s['items']:
                    self.fail_current('directory without full path'); return
                try:
                    parts=[safe_part(name,volume=(i==0)) for i,(_,name) in enumerate(s['items'])]
                    directory=safe_mkdir_tree(self.out,parts)
                except ValueError as e:
                    self.fail_current(str(e)); return
                self.dirs+=1
                self.log('directory',begin_seq=s['seq'],end_seq=seq,path=str(directory),
                         auxiliary_records=s['dir_aux_records'], auxiliary_bytes=s['dir_aux_bytes'])
                self.state=None; return
            if not s['data']:
                if s['short_acl'] is None or size!=0:
                    self.fail_current('OEND without content or inconsistent short ACL record'); return
                tmp=self.out/'.partial'/f'{s["seq"]:08d}.part'
                if tmp.exists() or tmp.is_symlink():
                    if self.resume and tmp.is_file() and not tmp.is_symlink():
                        tmp.unlink()
                        self.log('partial_restarted',begin_seq=s['seq'],path=str(tmp))
                    else:
                        self.fail_current(f'partial already exists: {tmp}'); return
                s['tmp']=tmp
                s['file']=tmp.open('xb')
                s['data']=True
                s['total']=0
                self.log('empty_file_acl',begin_seq=s['seq'],auxiliary_bytes=len(s['short_acl']))
            if size>s['total'] or s['total']-size>4096:
                self.fail_current(f'OEND size {size} does not match captured {s["total"]}'); return
            excess=s['total']-size
            s['file'].truncate(size)
            s['file'].flush(); os.fsync(s['file'].fileno()); s['file'].close(); s['file']=None
            try:
                if s['items']:
                    parts=[safe_part(name,volume=(i==0)) for i,(_,name) in enumerate(s['items'])]
                    if s['items'][-1][0]!=3: raise ValueError('non-file metadata for file data')
                    parent=safe_mkdir_tree(self.out,parts[:-1])
                    target=parent/parts[-1]
                else:
                    target=self.out/f'{s["seq"]:08d}_{safe_part(s["name"])}'
                if target.exists() or target.is_symlink():
                    raise ValueError(f'target already exists: {target}')
                # Hardlink-safe destination (no overwrite); rename confined under output.
                os.link(s['tmp'],target,follow_symlinks=False)
                s['tmp'].unlink()
            except (ValueError,OSError) as e:
                self.fail_current(f'could not commit: {e}'); return
            self.committed+=1
            if s['short_acl'] is not None:
                metadata_dir=safe_mkdir_tree(self.out,['.metadata'])
                raw_acl=metadata_dir/f'{s["seq"]:08d}.security.bin'
                try:
                    with raw_acl.open('xb') as raw:
                        raw.write(s['short_acl'])
                        raw.flush(); os.fsync(raw.fileno())
                    self.log('security_metadata',begin_seq=s['seq'],path=str(raw_acl),
                             bytes=len(s['short_acl']),sha256=hashlib.sha256(s['short_acl']).hexdigest())
                except OSError as e:
                    self.log('warning',begin_seq=s['seq'],reason=f'could not save raw security metadata: {e}')
            h=hashlib.sha256()
            with target.open('rb') as f:
                for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
            self.log('restored',begin_seq=s['seq'],end_seq=seq,path=str(target),
                     name=s['name'],bytes=size,trailer_bytes=excess,sha256=h.hexdigest())
            self.state=None



class CatalogRecovery:
    """Metadata-only Yosemite index. Never writes archive file contents."""
    def __init__(self, out, emit, source, resume=False):
        self.out=out; self.emit=emit; self.source=source; self.resume=resume
        self.prev_seq=None; self.state=None; self.errors=0
        self.committed=0; self.dirs=0; self.objects=0
        self.inflight_saved_count=0
        self.db=sqlite3.connect(str(out/'catalog.sqlite3'))
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS objects (
          begin_seq INTEGER PRIMARY KEY, end_seq INTEGER NOT NULL,
          kind TEXT NOT NULL, original_path TEXT NOT NULL, relative_path TEXT,
          size INTEGER NOT NULL, begin_offset INTEGER NOT NULL,
          metadata_offset INTEGER NOT NULL, end_offset INTEGER NOT NULL,
          source TEXT NOT NULL, status TEXT NOT NULL,
          content_records INTEGER NOT NULL,
          comment TEXT
        );
        CREATE TABLE IF NOT EXISTS records (
          seq INTEGER PRIMARY KEY, object_begin_seq INTEGER NOT NULL,
          byte_offset INTEGER NOT NULL, physical_block INTEGER NOT NULL,
          offset_in_block INTEGER NOT NULL, kind TEXT NOT NULL,
          flag INTEGER NOT NULL, payload_size INTEGER NOT NULL,
          logical INTEGER NOT NULL,
          FOREIGN KEY(object_begin_seq) REFERENCES objects(begin_seq)
        );
        CREATE INDEX IF NOT EXISTS idx_records_object ON records(object_begin_seq);
        """)
        self.db.commit()

    def log(self,event,**kw): self.emit(dict(event=event,**kw))

    def fail_current(self, reason):
        s=self.state
        if s is None: return
        self.log('incomplete',begin_seq=s['seq'],name=s['name'],reason=reason,temporary=None)
        self.errors+=1; self.state=None

    def handle(self,r,payload,byte_offset):
        seq=r['seq']
        if self.prev_seq is not None and seq != ((self.prev_seq+1)&0xffffffff):
            self.fail_current(f'sequence gap {self.prev_seq}->{seq}')
            self.log('sequence_gap',previous=self.prev_seq,current=seq)
        self.prev_seq=seq
        kind=r['kind']
        if kind=='OBGN':
            self.fail_current('new OBGN before OEND')
            self.inflight_saved_count=0
            self.objects+=1
            self.state=dict(seq=seq,name=f'object-{seq:08d}',items=None,
                 begin=byte_offset,meta_offset=None,records=[],content=0,first=True,
                 data_bytes=0,short_acl=False, invalid=None)
            self.log('begin',seq=seq)
        s=self.state
        if s is None: return
        s['records'].append((seq,s['seq'],byte_offset,byte_offset//BLOCK,
                             byte_offset%BLOCK,kind,r['flag'],r['size'],r['logical']))
        if kind=='DATU':
            if r['flag']==0:
                if s['items'] is not None:
                    s['invalid']='duplicate metadata DATU'
                else:
                    s['meta_offset']=byte_offset
                    s['items']=extract_path(payload)
                    s['name']=s['items'][-1][1] if s['items'] else short_name(payload,s['seq'])
                    self.log('metadata',begin_seq=s['seq'],name=s['name'],
                             path='/'.join(x[1] for x in s['items']) if s['items'] else None,
                             object_type=('directory' if s['items'] and s['items'][-1][0]==2 else 'file'),size=r['size'])
            else:
                s['content']+=1
                is_dir=bool(s['items'] and s['items'][-1][0]==2)
                if not is_dir:
                    if s['first']:
                        if len(payload)==220 and r['logical']==0 and payload[:12]==bytes.fromhex('0300000002000000c8000000'):
                            s['short_acl']=True
                        elif len(payload)>=240 and r['logical']==0:
                            s['data_bytes']+=len(payload)-240
                        else:
                            s['invalid']=f'invalid initial DATU: size={len(payload)}, logical={r["logical"]}'
                        s['first']=False
                    elif s['short_acl']:
                        s['invalid']='unexpected DATU after 220-byte ACL'
                    else:
                        s['data_bytes']+=len(payload)
        elif kind=='OEND':
            # A well-formed OEND is sufficient to index the object's position,
            # even if its content framing or declared length is not understood.
            if not s['items']:
                self.fail_current('missing full path metadata'); return
            is_dir=s['items'][-1][0]==2
            expected=r['logical']  # only the low 32 bits; never a verified >4GiB size
            reasons=[]
            if s['invalid']: reasons.append(s['invalid'])
            if is_dir and expected!=0:
                reasons.append('directory with nonzero logical size')
            size_delta=expected-s['data_bytes']
            size_variant_12=(not is_dir and not s['short_acl'] and
                             s['content']>0 and size_delta==12)
            if size_variant_12:
                self.log('size_variant_12',begin_seq=s['seq'],expected=expected,
                         observed=s['data_bytes'],note='unverified 12-byte DATU overhead variant')
            if not is_dir:
                if s['content']==0:
                    reasons.append('OEND without content')
                elif s['short_acl'] and expected!=0:
                    reasons.append('short ACL with nonzero OEND')
                elif not s['short_acl'] and not size_variant_12 and (
                        expected>s['data_bytes'] or s['data_bytes']-expected>4096):
                    reasons.append(f'inconsistent size: expected={expected}, observed={s["data_bytes"]}')

            # Preserve original path in the database even if an OS filename
            # cannot be materialized (e.g., components > 240 UTF-8 bytes).
            original='/'.join(x[1] for x in s['items'])
            parts=[]
            path_unsafe=False
            for i,(_,name) in enumerate(s['items']):
                try:
                    parts.append(safe_part(name,volume=(i==0)))
                except ValueError as exc:
                    reasons.append(f'path not materialized: {exc}')
                    path_unsafe=True
                    break
            if not path_unsafe:
                rel='/'.join(parts)
            else:
                rel=None

            # For ambiguous records the OEND low32 is NOT a valid full size.
            # Store measured DATU bytes as an estimate only when >=2^32, and
            # retain both numbers plus the ambiguity in comment JSON.
            ambiguous=bool(reasons)
            observed=s['data_bytes']
            est_large=(not is_dir and observed>=2**32 and
                       (observed-expected) % (2**32) <= 4096)
            if est_large:
                ambiguous=True
                reasons.append('OEND logical is 32-bit; full size unverified')
            stored_size=(observed if est_large else expected)
            status=('directory' if is_dir else 'unverified' if ambiguous else 'placeholder')
            if is_dir and ambiguous: status='unverified'
            comment=None
            if ambiguous:
                comment=json.dumps(dict(reasons=reasons, oend_logical32=expected,
                                        measured_datu_bytes=observed,
                                        estimated_large_size=est_large,
                                        materialized=False),ensure_ascii=False)
            elif s['short_acl']:
                comment='220-byte ACL-only DATU'
            elif size_variant_12:
                comment='UNVERIFIED: 12-byte size discrepancy'

            # Do not manufacture placeholder files for ambiguous data.
            # Filesystem failures must not prevent metadata indexing.
            if rel is not None and not ambiguous:
                try:
                    parent=safe_mkdir_tree(self.out,parts if is_dir else parts[:-1])
                    if not is_dir:
                        target=parent/parts[-1]
                        if target.exists() or target.is_symlink():
                            known=self.db.execute('SELECT begin_seq FROM objects WHERE relative_path=?',(rel,)).fetchone()
                            if known is None or known[0]!=s['seq']:
                                status='name_conflict'
                        else:
                            with target.open('xb'): pass
                except (ValueError,OSError) as exc:
                    status='unverified'
                    reasons.append(f'placeholder not materialized: {exc}')
                    comment=json.dumps(dict(reasons=reasons,oend_logical32=expected,
                                            measured_datu_bytes=observed,
                                            materialized=False),ensure_ascii=False)

            try:
                with self.db:
                    self.db.execute('''INSERT OR REPLACE INTO objects
                        (begin_seq,end_seq,kind,original_path,relative_path,size,begin_offset,
                         metadata_offset,end_offset,source,status,content_records,comment)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                        (s['seq'],seq,'directory' if is_dir else 'file',
                         original,rel,stored_size,s['begin'],s['meta_offset'],byte_offset,
                         self.source,status,s['content'],comment))
                    self.db.executemany('''INSERT OR REPLACE INTO records
                        (seq,object_begin_seq,byte_offset,physical_block,offset_in_block,
                         kind,flag,payload_size,logical) VALUES (?,?,?,?,?,?,?,?,?)''',s['records'])
            except sqlite3.Error as exc:
                self.fail_current(f'catalog commit failed: {exc}'); return

            if status=='unverified':
                self.log('cataloged_unverified',begin_seq=s['seq'],end_seq=seq,
                         path=original,reason='; '.join(reasons),
                         oend_logical32=expected,measured_datu_bytes=observed,
                         estimated_large_size=est_large)
            elif is_dir:
                self.log('directory',begin_seq=s['seq'],end_seq=seq,
                         path=str(self.out/rel),auxiliary_records=s['content'])
            else:
                self.log('cataloged',begin_seq=s['seq'],end_seq=seq,
                         path=str(self.out/rel),bytes=stored_size,
                         placeholder=(status=='placeholder'),status=status)
            if is_dir: self.dirs+=1
            else: self.committed+=1
            self.state=None

    def save_inflight(self, state, offset, prev_seq):
        """Commit SQLite first; checkpoint.json will publish the returned snapshot id.

        Old snapshots remain readable if the process crashes before JSON rename.
        The record table is append/upsert-only until a completed-object checkpoint.
        """
        self.db.execute('''CREATE TABLE IF NOT EXISTS inflight_records (
            object_begin_seq INTEGER NOT NULL,
            record_idx INTEGER NOT NULL,
            seq INTEGER NOT NULL,
            object_seq INTEGER NOT NULL,
            byte_offset INTEGER NOT NULL,
            physical_block INTEGER NOT NULL,
            offset_in_block INTEGER NOT NULL,
            kind TEXT NOT NULL,
            flag INTEGER NOT NULL,
            payload_size INTEGER NOT NULL,
            logical INTEGER NOT NULL,
            PRIMARY KEY(object_begin_seq,record_idx)
        )''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS inflight_snapshots (
            id INTEGER PRIMARY KEY,
            object_begin_seq INTEGER NOT NULL,
            record_count INTEGER NOT NULL,
            byte_offset INTEGER NOT NULL,
            previous_seq INTEGER NOT NULL,
            state_json TEXT NOT NULL
        )''')
        begin=state['seq']
        # rec.state records must not change between SQLite commit and JSON publication.
        records=state['records']
        state_meta={k:v for k,v in state.items() if k!='records'}
        start=self.inflight_saved_count if self.inflight_saved_count<=len(records) else 0
        with self.db:
            self.db.executemany('''INSERT OR REPLACE INTO inflight_records
                (object_begin_seq,record_idx,seq,object_seq,byte_offset,
                 physical_block,offset_in_block,kind,flag,payload_size,logical)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                ((begin,i,*records[i]) for i in range(start,len(records))))
            cur=self.db.execute('''INSERT INTO inflight_snapshots
                (object_begin_seq,record_count,byte_offset,previous_seq,state_json)
                VALUES (?,?,?,?,?)''',
                (begin,len(records),offset,prev_seq,json.dumps(state_meta,ensure_ascii=False)))
            snapshot_id=cur.lastrowid
        self.inflight_saved_count=len(records)
        return snapshot_id

    def load_inflight(self, snapshot_id, offset, prev_seq):
        snap=self.db.execute('''SELECT object_begin_seq,record_count,byte_offset,
            previous_seq,state_json FROM inflight_snapshots WHERE id=?''',
            (snapshot_id,)).fetchone()
        if snap is None or snap[2]!=offset or snap[3]!=prev_seq:
            raise ValueError('SQLite snapshot does not match checkpoint.json')
        begin,count=snap[0],snap[1]
        rows=self.db.execute('''SELECT seq,object_seq,byte_offset,physical_block,
            offset_in_block,kind,flag,payload_size,logical
            FROM inflight_records WHERE object_begin_seq=? AND record_idx<?
            ORDER BY record_idx''',(begin,count)).fetchall()
        if len(rows)!=count:
            raise ValueError(f'incomplete SQLite inflight records: {len(rows)} != {count}')
        state=json.loads(snap[4]);state['records']=[tuple(row) for row in rows]
        if state['seq']!=begin:
            raise ValueError('snapshot object identity mismatch')
        self.inflight_saved_count=count
        return state

    def clean_inflight(self):
        # Called only after completed-object checkpoint.json is committed.
        with self.db:
            self.db.execute('DELETE FROM inflight_records')
            self.db.execute('DELETE FROM inflight_snapshots')
        self.inflight_saved_count=0

    def close(self): self.db.close()

def log_emitter(log):
    def emit(event):
        log.write(json.dumps(event,ensure_ascii=False)+'\n'); log.flush()
    return emit


def checkpoint_write(path,source,base,prev_seq,stats,mode="restore",in_progress=None,catalog_rec=None):
    tmp=path.with_suffix('.tmp')
    obj=dict(version=2,mode=mode,source=source,byte_offset=base,physical_block=base//BLOCK,
             offset_in_block=base%BLOCK,previous_seq=prev_seq,stats=stats)
    if in_progress is not None:
        if mode != 'catalog':
            raise ValueError('in-progress checkpoint is catalog-only')
        if catalog_rec is None:
            raise ValueError('catalog recovery required for SQLite inflight checkpoint')
        obj['in_progress_ref'] = catalog_rec.save_inflight(in_progress,base,prev_seq)
    with tmp.open('w') as f:
        json.dump(obj,f,indent=2); f.flush(); os.fsync(f.fileno())
    os.replace(tmp,path)
    # Make renamed checkpoint durable across power loss, where supported.
    dfd=os.open(str(path.parent),os.O_RDONLY)
    try: os.fsync(dfd)
    finally: os.close(dfd)


def tape_capacity_snapshot(tape):
    """Best effort, non-positioning LTO LOG SENSE tape-capacity diagnostics."""
    import shutil
    if not shutil.which('sg_logs'):
        return {'available': False, 'reason': 'sg_logs not installed'}
    # Tape and its associated sg generic node may be named independently.
    import re as _re
    m = _re.fullmatch(r'/dev/nst(\d+)', tape)
    sg = None
    if m:
        sysfs = Path('/sys/class/scsi_tape') / ('nst'+m.group(1)) / 'device/scsi_generic'
        if sysfs.exists():
            names = list(sysfs.iterdir())
            if names: sg = '/dev/'+names[0].name
    if not sg:
        return {'available': False, 'reason': 'could not resolve scsi_generic device'}
    try:
        proc = subprocess.run(['sg_logs','-p','0x31',sg],capture_output=True,
                              text=True,timeout=15,check=False)
    except (OSError,subprocess.TimeoutExpired) as e:
        return {'available': False, 'reason': str(e)}
    if proc.returncode:
        return {'available': False, 'reason': proc.stderr.strip()[:300]}
    vals={}
    for line in proc.stdout.splitlines():
        m=_re.search(r'Native capacity from BOP to (EOD|current position):\s*(\d+)\s*MB',line,_re.I)
        if m: vals['eod_mb' if m.group(1).upper()=='EOD' else 'position_mb']=int(m.group(2))
    return {'available': bool(vals), 'sg_device':sg, **vals}


def eio_assessment(tape):
    cap=tape_capacity_snapshot(tape)
    eod=cap.get('eod_mb'); pos=cap.get('position_mb')
    # This is merely an indication, not proof. No media-health counter alone
    # can reliably distinguish EOD from a drive/medium error.
    near=(eod is not None and pos is not None and eod>0 and abs(eod-pos)<=8)
    return {'classification':'probable_eod' if near else 'io_error',
            'reason':'capacity proximity; SCSI sense not captured' if near else
                     'no corroborating EOD capacity measurement',
            'capacity':cap}


def source_blocks(args,offset):
    # Returns chunks read; single reader, no offset assumptions inside physical record.
    if args.tape:
        if offset:
            block=offset//BLOCK
            subprocess.run(['mt','-f',args.tape,'rewind'],check=True)
            # SPACE(6) has signed 24-bit count. Chunk for large tape locations.
            while block:
                step=min(block,1000000)
                subprocess.run(['mt','-f',args.tape,'fsr',str(step)],check=True)
                block-=step
        else:
            subprocess.run(['mt','-f',args.tape,'rewind'],check=True)
        fd=os.open(args.tape,os.O_RDONLY | getattr(os,'O_CLOEXEC',0))
        try:
            count=0
            while count<args.max_blocks:
                chunk=os.read(fd,BLOCK)
                if not chunk:
                    args._source_end_reason='zero_read_or_filemark_or_eod'
                    break  # filemark/EOD; do not cross automatically
                if len(chunk)!=BLOCK:
                    raise IOError(f'Unexpected physical record size {len(chunk)} (expected {BLOCK})')
                count+=1
                yield chunk
            else:
                args._source_end_reason='max_blocks_reached'
        finally: os.close(fd)
    else:
        with args.input.open('rb') as f:
            f.seek(offset//BLOCK*BLOCK)
            while True:
                chunk=f.read(4*1024*1024)
                if not chunk:
                    args._source_end_reason='input_complete'
                    break
                yield chunk


def recover(args):
    out=args.out
    out.mkdir(parents=True,exist_ok=True)
    checkpoint=out/'checkpoint.json'
    logpath=out/'recovery.jsonl'
    source=args.tape if args.tape else str(args.input.resolve())
    offset=0; previous=None
    if args.resume:
        c=json.loads(checkpoint.read_text())
        if c.get('mode','restore') != ('catalog' if args.catalog_only else 'restore'):
            raise ValueError('checkpoint mode mismatch (--catalog-only)')
        if c['source']!=source: raise ValueError('checkpoint belongs to another source')
        offset=c['byte_offset']; previous=c['previous_seq']
        if args.tape and offset%BLOCK and not args.tape.startswith('/dev/nst'):
            raise ValueError('use the non-rewinding tape device /dev/nst*')
    elif checkpoint.exists() or logpath.exists():
        raise FileExistsError('output already has a journal/checkpoint; choose new --out or --resume')
    if args.resume and offset==0 and previous is None:
        raise ValueError('no completed object checkpoint to resume from')
    if args.tape and args.max_blocks<=0: raise ValueError('--max-blocks must be positive')
    with logpath.open('a' if args.resume else 'x',encoding='utf-8') as logfile:
        rec=(CatalogRecovery(out,log_emitter(logfile),source,resume=args.resume) if args.catalog_only
             else Recovery(out,log_emitter(logfile),resume=args.resume)); rec.prev_seq=previous
        if args.resume and args.catalog_only:
            if c.get('in_progress_ref') is not None:
                state=rec.load_inflight(c['in_progress_ref'],offset,previous)
            else:
                state=c.get('in_progress')  # Read legacy v1 checkpoints unchanged.
            if state is not None:
                if not isinstance(state,dict) or not isinstance(state.get('records'),list):
                    raise ValueError('invalid in-progress checkpoint')
                if state.get('seq') is None or state.get('items') is None:
                    raise ValueError('incomplete in-progress checkpoint')
                rec.state=state
                rec.log('object_resumed',begin_seq=state['seq'],
                        records=len(state['records']),offset=offset)
        rec.log('session',source=source,resume=args.resume,offset=offset)
        buf=bytearray(); base=offset//BLOCK*BLOCK; eof=False; aligned=False; skipped=offset%BLOCK
        stop_reason=None; read_error=None
        iterator=iter(source_blocks(args,offset))
        try:
            while True:
                if not eof and len(buf)<MAX_DATA+HEADER+BLOCK:
                    try: chunk=next(iterator)
                    except StopIteration:
                        eof=True
                        stop_reason=getattr(args,'_source_end_reason','iterator_exhausted')
                    except OSError as e:
                        eof=True; read_error=e
                        stop_reason='read_io_error'
                    else:
                        if skipped:
                            chunk=chunk[skipped:]; base+=skipped; skipped=0
                        buf.extend(chunk)
                if not aligned:
                    idx=buf.find(MAGIC)
                    if idx<0:
                        if eof: break
                        discard=max(0,len(buf)-HEADER)
                        del buf[:discard]; base+=discard; continue
                    if len(buf)-idx<HEADER:
                        if eof: break
                        del buf[:idx]; base+=idx; continue
                    r=parse_header(buf,idx)
                    if r is None:
                        del buf[:idx+1]; base+=idx+1; continue
                    del buf[:idx]; base+=idx; aligned=True
                r=parse_header(buf)
                if r is None:
                    rec.fail_current(f'invalid header at source offset {base}')
                    aligned=False; del buf[0:1]; base+=1; continue
                needed=HEADER+((r['size']+63)//64)*64
                if len(buf)<needed:
                    if eof:
                        # A session limit is not a damaged tape record.
                        # The next resume must re-read this incomplete record.
                        if (args.catalog_only and
                                stop_reason == 'max_blocks_reached'):
                            rec.log(
                                'partial_record_deferred',
                                byte_offset=base,
                                buffered_bytes=len(buf),
                                required_bytes=needed
                            )
                        else:
                            rec.fail_current(
                                f'truncated record at byte {base}'
                            )
                        break
                    continue
                prev_completed=rec.committed+rec.dirs
                if args.catalog_only:
                    rec.handle(r,bytes(buf[HEADER:HEADER+r['size']]),base)
                else:
                    rec.handle(r,bytes(buf[HEADER:HEADER+r['size']]))
                del buf[:needed]; base+=needed
                if rec.committed+rec.dirs>prev_completed and rec.state is None:
                    checkpoint_write(checkpoint,source,base,rec.prev_seq,
                                     {'restored_this_run':rec.committed,'directories_this_run':rec.dirs},
                                     mode='catalog' if args.catalog_only else 'restore')
                    if args.catalog_only:
                        rec.clean_inflight()
                if (args.catalog_only and rec.state is not None
                        and len(rec.state['records']) % 1024 == 0):
                    checkpoint_write(
                        checkpoint, source, base, rec.prev_seq,
                        {'restored_this_run': rec.committed,
                         'directories_this_run': rec.dirs},
                        mode='catalog',
                        in_progress=rec.state,
                        catalog_rec=rec
                    )
            # Record the terminal condition. EIO near drive-reported EOD is
            # probable EOD only; no fully conclusive classification without
            # original REQUEST SENSE from the failing READ command.
            if read_error is not None:
                assessment=eio_assessment(args.tape) if args.tape else {'classification':'io_error'}
                rec.log('source_error',errno=read_error.errno,error=str(read_error),
                        byte_offset=base,classification=assessment['classification'],
                        diagnostics=assessment)
                stop_reason=assessment['classification']
            elif args.tape and stop_reason is None:
                stop_reason='max_blocks_reached'
            elif stop_reason is None:
                stop_reason='input_complete'
            if args.tape and stop_reason=='zero_read_or_filemark_or_eod':
                rec.log('note',message='zero-length tape read may indicate a filemark, not true EOD')
            if rec.state is not None:
                if args.catalog_only and stop_reason == 'max_blocks_reached':
                    checkpoint_write(
                        checkpoint, source, base, rec.prev_seq,
                        {'restored_this_run': rec.committed,
                         'directories_this_run': rec.dirs},
                        mode='catalog',
                        in_progress=rec.state,
                        catalog_rec=rec
                    )
                    rec.log(
                        'intermediate_checkpoint',
                        begin_seq=rec.state['seq'],
                        byte_offset=base,
                        previous_seq=rec.prev_seq,
                        records=len(rec.state['records'])
                    )
                rec.fail_current(f'source stopped ({stop_reason}) before OEND at byte {base}')
            rec.log('source_end',reason=stop_reason,byte_offset=base,
                    last_seen_seq=rec.prev_seq,checkpoint=str(checkpoint),
                    checkpoint_exists=checkpoint.exists())
            rec.log('summary',objects_started=rec.objects,restored=rec.committed,
                    directories=rec.dirs,incomplete=rec.errors,mode='catalog' if args.catalog_only else 'restore',
                    stop_reason=stop_reason)
            return rec.committed,rec.errors
        finally:
            if args.catalog_only: rec.close()
            close=getattr(iterator,'close',None)
            if close: close()




def extract_indexed(args):
    "Read exactly one indexed Yosemite object (strict, read-only extraction)."
    if args.resume or args.catalog_only:
        raise ValueError('--extract-seq cannot be combined with --resume or --catalog-only')
    if args.catalog is None:
        raise ValueError('--extract-seq requires --catalog')
    if not args.catalog.is_file():
        raise ValueError(f'catalog not found: {args.catalog}')
    with sqlite3.connect(f'file:{args.catalog.resolve()}?mode=ro', uri=True) as db:
        row=db.execute('''SELECT begin_seq,end_seq,kind,original_path,size,
                          begin_offset,end_offset,status,comment,source
                          FROM objects WHERE begin_seq=?''',(args.extract_seq,)).fetchone()
        if row is None: raise ValueError(f'begin_seq {args.extract_seq} not found')
        begin_seq,end_seq,kind,path,expected,begin,end,status,comment,source=row
        if kind!='file' or status!='placeholder':
            raise ValueError(f'object status={status}, kind={kind}; only placeholder files are supported')
        if comment is not None:
            raise ValueError(f'unsupported/unverified size variant: {comment}')
        if args.tape and source!=args.tape:
            raise ValueError(f'catalog source={source!r} does not match tape {args.tape!r}')
        if begin<0 or end<begin or expected<0:
            raise ValueError('invalid catalog offsets or size')
        records=db.execute('''SELECT seq,byte_offset,kind,flag,payload_size,logical
                  FROM records WHERE object_begin_seq=? ORDER BY byte_offset''',(begin_seq,)).fetchall()
    if not records or records[0][1]!=begin or records[-1][1]!=end:
        raise ValueError('incomplete indexed record range')
    if records[0][2]!='OBGN' or records[-1][2]!='OEND':
        raise ValueError('object boundary records missing')
    if records[0][0]!=begin_seq or records[-1][0]!=end_seq:
        raise ValueError('catalog object sequence mismatch')
    if len(records)<4:
        raise ValueError('unexpectedly short object record sequence')

    output=args.out
    output.mkdir(parents=True,exist_ok=True)
    name=path.rsplit('/',1)[-1]
    try: name=safe_part(name)
    except ValueError: name=f'object-{begin_seq}.bin'
    # Prefix by sequence to avoid ambiguity between identical names.
    dest=output/f'{begin_seq}_{name}'
    partial=output/f'.{begin_seq}_{name}.partial'
    if dest.exists() or dest.is_symlink() or partial.exists() or partial.is_symlink():
        raise FileExistsError(f'output already exists: {dest} or {partial}')

    # source_blocks positions at the containing physical block; preserve exact
    # logical offset independently of the drive's 64KiB physical boundaries.
    args.max_blocks=max(1,(end//BLOCK - begin//BLOCK)+2+(MAX_DATA//BLOCK))
    chunks=iter(source_blocks(args,begin))
    buffer=bytearray()
    cursor=(begin//BLOCK)*BLOCK
    skip=begin%BLOCK
    h=hashlib.sha256()
    written=0
    first_content=True
    metadata_seen=False
    content_seen=False
    logical_next=0
    trailer=bytearray()
    result=None
    try:
        with partial.open('xb') as outf:
            for index,(seq,offset,kind,flag,payload_size,logical) in enumerate(records):
                while len(buffer)<HEADER:
                    try: chunk=next(chunks)
                    except StopIteration: raise ValueError('source ended before indexed record completed')
                    if skip: chunk=chunk[skip:];cursor+=skip;skip=0
                    buffer.extend(chunk)
                if cursor!=offset:
                    raise ValueError(f'record offset mismatch: {cursor} != {offset}')
                hdr=parse_header(buffer)
                if hdr is None:
                    raise ValueError(f'invalid Yosemite header at {offset}')
                needed=HEADER+((hdr['size']+63)//64)*64
                while len(buffer)<needed:
                    try: chunk=next(chunks)
                    except StopIteration: raise ValueError('source ended before indexed record completed')
                    if skip: chunk=chunk[skip:];cursor+=skip;skip=0
                    buffer.extend(chunk)
                if (hdr['seq'],hdr['kind'],hdr['flag'],hdr['size'],hdr['logical'])!=(seq,kind,flag,payload_size,logical):
                    raise ValueError(f'catalog/tape record disagreement at {offset}')
                if kind=='DATU' and flag==0:
                    if content_seen or metadata_seen:
                        raise ValueError('duplicate or late metadata DATU')
                    meta=bytes(buffer[HEADER:HEADER+payload_size])
                    items=extract_path(meta)
                    if not items or '/'.join(x[1] for x in items)!=path:
                        raise ValueError('catalog/tape original path mismatch')
                    metadata_seen=True
                elif kind=='DATU' and flag==1:
                    if not metadata_seen: raise ValueError('content before metadata')
                    raw=memoryview(buffer)[HEADER:HEADER+payload_size]
                    if first_content:
                        if logical!=0 or payload_size<40:
                            raise ValueError('unsupported initial DATU format')
                        prefix=int.from_bytes(raw[8:12], 'little')+40
                        if prefix<40 or prefix>payload_size:
                            raise ValueError(f'invalid DATU metadata prefix: {prefix}')
                        data=raw[prefix:prefix+min(expected-written,payload_size-prefix)]
                        trailer.extend(raw[prefix+len(data):])
                        first_content=False
                    else:
                        if logical!=logical_next:
                            raise ValueError(f'Yosemite logical DATU offset mismatch at {offset}')
                        n=min(expected-written,payload_size)
                        data=raw[:n]
                        trailer.extend(raw[n:])
                    outf.write(data)
                    h.update(data)
                    written+=len(data)
                    logical_next+=payload_size
                    content_seen=True
                    del data,raw
                elif kind=='OEND':
                    if not content_seen or not metadata_seen or logical!=expected:
                        raise ValueError('missing content or OEND size disagreement')
                elif kind!='OBGN':
                    raise ValueError(f'unexpected record {kind}')
                del buffer[:needed]
                cursor+=needed
            if written!=expected:
                raise ValueError(f'extracted size {written} differs from catalog size {expected}')
            marker=b'$KERNEL.PURGE.DRWEB_HASH_INFO\x00'
            validation='record headers, offsets, path, size (no original checksum)'
            if marker in trailer:
                digest=h.digest()
                pos=trailer.find(marker)+len(marker)
                if trailer.find(digest,pos)<0:
                    raise ValueError('DRWEB_HASH_INFO is present but restored file SHA-256 does not match')
                validation='record headers, offsets, path, size, tape SHA-256'

            outf.flush();os.fsync(outf.fileno())
        os.link(partial,dest,follow_symlinks=False)
        partial.unlink()
        result=dict(begin_seq=begin_seq, original_path=path, bytes=written,
                    sha256=h.hexdigest(),output=str(dest),
                    validation=validation)
    except (Exception,BaseException):
        try: partial.unlink(missing_ok=True)
        except OSError: pass
        raise
    finally:
        close=getattr(chunks,'close',None)
        if close: close()
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return 0

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--input',type=Path,help='captured binary file')
    group.add_argument('--tape',help='non-rewinding tape, e.g. /dev/nst0')
    ap.add_argument('--out',required=True,type=Path)
    ap.add_argument('--extract-seq',type=int,help='extract one verified indexed object by begin_seq')
    ap.add_argument('--catalog',type=Path,help='SQLite catalog for --extract-seq')
    ap.add_argument('--resume',action='store_true',help='resume at last completed object checkpoint')
    ap.add_argument('--catalog-only',action='store_true',help='create empty placeholder files and SQLite tape index, no payload extraction')
    ap.add_argument('--max-blocks',type=int,default=4096,help='maximum 64KiB tape records per session (default 4096)')
    args=ap.parse_args()
    if args.tape and args.tape!='/dev/nst0' and not re.fullmatch(r'/dev/nst\d+',args.tape):
        ap.error('tape must be /dev/nstN (not /dev/stN)')
    if args.input and not args.input.is_file(): ap.error('missing capture file')
    try:
        if args.extract_seq is not None:
            return extract_indexed(args)
        if args.catalog is not None:
            raise ValueError('--catalog is only valid with --extract-seq')
        restored,failed=recover(args)
        print(f'{"Cataloged" if args.catalog_only else "Restored"} {restored} files, incomplete/failed {failed}. Log: {args.out}/recovery.jsonl')
    except (ValueError,FileExistsError,OSError,subprocess.CalledProcessError) as e:
        ap.exit(2,f'ERROR: {e}\n')

if __name__=='__main__': main()
