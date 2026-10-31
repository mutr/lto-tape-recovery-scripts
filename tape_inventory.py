#!/usr/bin/env python3
"""Read-only inventory of existing LTO recovery directories.

Uses Python standard library only. Never opens tape devices or runs mt/sg utilities.
Database changes are limited to the inventory SQLite database.
"""
import argparse
import csv
import datetime as dt
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path

DEFAULT_ROOT = Path('/root/tape-recovery')
SCHEMA_VERSION = 2
SCHEMA = '''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS media (
 id INTEGER PRIMARY KEY,
 directory_name TEXT UNIQUE NOT NULL,
 barcode TEXT,
 volume_serial TEXT,
 generation INTEGER,
 manufacturer TEXT,
 archive_format TEXT,
 backup_name TEXT,
 catalog_path TEXT,
 first_seen_utc TEXT NOT NULL,
 updated_at_utc TEXT NOT NULL,
 notes TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_media_serial ON media(volume_serial) WHERE volume_serial IS NOT NULL;
CREATE TABLE IF NOT EXISTS barcode_history (
 id INTEGER PRIMARY KEY, media_id INTEGER NOT NULL REFERENCES media(id),
 barcode TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('current','previous','observed')),
 observed_at_utc TEXT, source TEXT NOT NULL,
 UNIQUE(media_id,barcode,role,source)
);
CREATE TABLE IF NOT EXISTS drives (
 id INTEGER PRIMARY KEY, serial TEXT UNIQUE NOT NULL, manufacturer TEXT, model TEXT,
 firmware TEXT
);
CREATE TABLE IF NOT EXISTS telemetry (
 id INTEGER PRIMARY KEY, media_id INTEGER NOT NULL REFERENCES media(id),
 collected_at_utc TEXT NOT NULL, snapshot_path TEXT NOT NULL,
 source_fingerprint TEXT NOT NULL,
 drive_id INTEGER REFERENCES drives(id),
 mounts INTEGER, bop_passes INTEGER, mop_passes INTEGER,
 datasets_written INTEGER, datasets_read INTEGER,
 write_retries INTEGER, read_retries INTEGER,
 unrecovered_write_errors INTEGER, unrecovered_read_errors INTEGER,
 used_native_mb INTEGER, total_native_mb INTEGER,
 remaining_mib INTEGER, max_capacity_mib INTEGER,
 barcode_observed TEXT, volume_serial_observed TEXT,
 tape_alert_nonzero TEXT, raw_files_json TEXT NOT NULL,
 UNIQUE(media_id,snapshot_path)
);
CREATE TABLE IF NOT EXISTS catalogs (
 id INTEGER PRIMARY KEY, media_id INTEGER NOT NULL REFERENCES media(id),
 catalog_path TEXT NOT NULL, checkpoint_path TEXT,
 objects_total INTEGER, directories INTEGER, placeholders INTEGER, restored INTEGER,
 max_seq INTEGER, checkpoint_offset INTEGER, physical_block INTEGER,
 catalog_mode TEXT, indexed_at_utc TEXT, observed_at_utc TEXT NOT NULL,
 UNIQUE(media_id,catalog_path)
);
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY, media_id INTEGER REFERENCES media(id),
 event_at_utc TEXT, type TEXT NOT NULL, details_json TEXT NOT NULL,
 source TEXT, event_key TEXT UNIQUE NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_tel_media_time ON telemetry(media_id,collected_at_utc);
CREATE INDEX IF NOT EXISTS ix_events_media_time ON events(media_id,event_at_utc);
'''
FIELDS = {
 'Thread count': 'mounts',
 'Beginning of medium passes': 'bop_passes',
 'Middle of medium passes': 'mop_passes',
 'Total data sets written': 'datasets_written',
 'Total data sets read': 'datasets_read',
 'Total write retries': 'write_retries',
 'Total read retries': 'read_retries',
 'Total unrecovered write errors': 'unrecovered_write_errors',
 'Total unrecovered read errors': 'unrecovered_read_errors',
 'Total used native capacity': 'used_native_mb',
 'Total native capacity': 'total_native_mb',
 'Main partition remaining capacity (in MiB)': 'remaining_mib',
 'Main partition maximum capacity (in MiB)': 'max_capacity_mib',
 'Volume barcode': 'barcode_observed',
 'Volume serial number': 'volume_serial_observed',
}
ALLOWED = {'media-info.json','checkpoint.json','collected-at.txt','volume-statistics.txt','tape-capacity.txt', 'tape-usage.txt','tape-alert.txt','sg-log-17.txt','sg-log-30.txt','sg-log-31.txt','sg-log-2e.txt','sg-log-33.txt','sg-log-34.txt','read-errors.txt','write-errors.txt','cartridge-memory.txt','tape-status.txt'}

def now(): return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')

def utc_from_stamp(s):
 try: return dt.datetime.strptime(s,'%Y%m%dT%H%M%SZ').replace(tzinfo=dt.timezone.utc).isoformat(timespec='seconds')
 except ValueError: return None

def clean(x): return str(x).strip() if x is not None and str(x).strip() else None

def read_json(path):
 try: return json.loads(path.read_text(encoding='utf-8'))
 except (OSError,ValueError) as ex:
  print(f'WARN: cannot parse {path}: {ex}',file=sys.stderr); return {}

def parse_logs(path):
 metrics = {}; raw = {}; h=hashlib.sha256()
 for p in sorted(path.iterdir()):
  if not p.is_file() or p.name not in ALLOWED: continue
  if p.stat().st_size>4*1024*1024:
   print(f'WARN: skip oversized {p}',file=sys.stderr); continue
  b=p.read_bytes(); h.update(p.name.encode()+b'\0'+b)
  raw[p.name]=str(p)
  if p.suffix!='.txt': continue
  txt=b.decode('utf-8',errors='replace')
  for line in txt.splitlines():
   if ':' not in line: continue
   key,val=(x.strip() for x in line.split(':',1))
   if key not in FIELDS: continue
   field=FIELDS[key]
   if field in ('barcode_observed','volume_serial_observed'): metrics[field]=clean(val)
   else:
    match=re.search(r'(?<!\w)(\d+)(?!\w)',val)
    if match: metrics[field]=int(match.group(1))
  if p.name in ('tape-alert.txt','sg-log-2e.txt'):
   alert={}
   for line in txt.splitlines():
    m=re.match(r'^\s*([^:]+):\s*([1-9]\d*)\s*$',line)
    if m: alert[m.group(1).strip()]=int(m.group(2))
   metrics['tape_alert_nonzero']=json.dumps(alert,ensure_ascii=False,sort_keys=True)
  if p.name in ('volume-statistics.txt','sg-log-17.txt'):
   serials=re.findall(r'unit serial number:\s*(\S+)',txt,re.I)
   if serials: metrics['drive_serial']=serials[0]
  mm=re.search(r'\bHP\s+Ultrium\s+([\w-]+)\s+([\w.]+)',txt)
  if mm: metrics.setdefault('drive_model','Ultrium '+mm.group(1)); metrics.setdefault('drive_firmware',mm.group(2))
 return metrics,raw,h.hexdigest()

def db_connect(path):
 path.parent.mkdir(parents=True,exist_ok=True)
 c=sqlite3.connect(path);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');c.execute('PRAGMA busy_timeout=5000')
 c.executescript(SCHEMA)
 # Additive database migration.
 v=c.execute('SELECT version FROM schema_version').fetchone()
 if v and v[0] not in (1, 2):
  raise RuntimeError(f'unsupported schema version {v[0]}')
 additions={
  'files_total':'INTEGER',
  'size_known_files':'INTEGER',
  'size_known_bytes':'INTEGER',
  'tape_file_first':'INTEGER',
  'tape_file_last':'INTEGER',
 }
 current={r[1] for r in c.execute('PRAGMA table_info(catalogs)')}
 for col, typ in additions.items():
  if col not in current:
   c.execute(f'ALTER TABLE catalogs ADD COLUMN {col} {typ}')
 if v:
  c.execute('UPDATE schema_version SET version=2')
 else:
  c.execute('INSERT INTO schema_version VALUES(2)')
 return c

def event(conn,media_id,typ,detail,source,date=None):
 data=json.dumps(detail,sort_keys=True,ensure_ascii=False)
 key=hashlib.sha256(f'{media_id}\0{typ}\0{source}\0{data}'.encode()).hexdigest()
 conn.execute('INSERT OR IGNORE INTO events(media_id,event_at_utc,type,details_json,source,event_key) VALUES(?,?,?,?,?,?)',(media_id,date,typ,data,source,key))

def add_history(conn,mid,code,role,src,date=None):
 if code: conn.execute('INSERT OR IGNORE INTO barcode_history(media_id,barcode,role,observed_at_utc,source) VALUES(?,?,?,?,?)',(mid,code,role,date,src))

def catalog_info(path):
 """Summarize heterogeneous SQLite recovery catalogs without assuming a fixed schema.

 Yosemite objects use end_seq/status. DIVA objects may have a different schema.
 Missing attributes are represented as NULL rather than fabricated zero counts.
 """
 con=sqlite3.connect(f'file:{path.as_posix()}?mode=ro',uri=True)
 try:
  tables={r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
  if 'objects' not in tables:
   raise ValueError(f'{path}: missing objects table')
  cols={r[1] for r in con.execute('PRAGMA table_info(objects)')}
  total=con.execute('SELECT COUNT(*) FROM objects').fetchone()[0]
  def status_count(status):
   if 'status' not in cols: return None
   return con.execute('SELECT COUNT(*) FROM objects WHERE status=?',(status,)).fetchone()[0]
  # A catalog may use seq rather than end_seq. Do not confuse a row id
  # with the parser's sequence number; NULL means not available.
  seqcol=next((x for x in ('end_seq','seq','sequence') if x in cols),None)
  maxseq=con.execute(f'SELECT MAX("{seqcol}") FROM objects').fetchone()[0] if seqcol else None
  return (total,status_count('directory'),status_count('placeholder'),
          status_count('restored'),maxseq)
 finally: con.close()

def catalog_extra(path):
 con=sqlite3.connect(f'file:{path.as_posix()}?mode=ro',uri=True)
 try:
  cols={r[1] for r in con.execute('PRAGMA table_info(objects)')}
  if {'tape_barcode','metadata_file','data_file','size_bytes'}.issubset(cols):
   r=con.execute(
    'SELECT COUNT(*),COUNT(size_bytes),SUM(size_bytes),'
    'MIN(data_file),MAX(data_file) FROM objects'
   ).fetchone()
   return tuple(r)
  if {'kind','size'}.issubset(cols):
   r=con.execute(
    "SELECT COUNT(*),COUNT(size),SUM(size) "
    "FROM objects WHERE kind='file'"
   ).fetchone()
   return (r[0],r[1],r[2],None,None)
  return (None,None,None,None,None)
 finally:
  con.close()

def detect_format(folder,meta):
 if clean(meta.get('backup_format')):
  return clean(meta['backup_format'])
 catalog=folder/'catalog'/'catalog.sqlite3'
 if catalog.is_file():
  con=sqlite3.connect(f'file:{catalog.as_posix()}?mode=ro',uri=True)
  try:
   cols={r[1] for r in con.execute('PRAGMA table_info(objects)')}
   if {'tape_barcode','metadata_file','data_file',
       'original_path','placeholder_path'}.issubset(cols):
    return 'DIVA'
   if {'begin_seq','end_seq','kind','size','status'}.issubset(cols):
    return 'Yosemite Server Backup'
  finally:
   con.close()
 p=folder/'probe'/'first-block.bin'
 try:
  head=p.open('rb').read(4096)
 except OSError:
  return None
 if head.startswith(b'F700\\x00\\x00\\x00\\x00MHDR'):
  return 'Yosemite Server Backup'
 return None

def archive_name(folder,meta):
 if clean(meta.get('backup_name')): return clean(meta['backup_name'])
 p=folder/'probe'/'first-block.bin'
 try: b=p.open('rb').read(512)
 except OSError: return None
 if b.startswith(b'F700\x00\x00\x00\x00MHDR'):
  return clean(b[64:160].split(b'\x00',1)[0].decode('utf-8',errors='replace'))
 return None

def scan_folder(conn,root,folder):
 meta=read_json(folder/'media-info.json') if (folder/'media-info.json').is_file() else {}
 bar=clean(meta.get('barcode')) or (folder.name if re.fullmatch(r'[A-Z0-9]{6}L[4-9]',folder.name) else None)
 prev=clean(meta.get('previous_barcode'))
 arch=detect_format(folder,meta)
 name=archive_name(folder,meta)
 tdirs=sorted([p for p in (folder/'telemetry').glob('*') if p.is_dir()]) if (folder/'telemetry').is_dir() else []
 entries=[]
 for td in tdirs:
  m,r,h=parse_logs(td)
  if not r: continue
  entries.append((td,m,r,h))
 latest=entries[-1][1] if entries else {}
 serial=clean(meta.get('volume_serial')) or clean(latest.get('volume_serial_observed'))
 gen=int(bar[-1]) if bar and re.fullmatch(r'[A-Z0-9]{6}L[4-9]',bar) else None
 ftime=utc_from_stamp(entries[0][0].name) if entries else None
 catalog=folder/'catalog'/'catalog.sqlite3'
 if not catalog.is_file(): catalog=None
 if not (catalog or entries or (folder/'media-info.json').is_file() or (folder/'probe'/'first-block.bin').is_file()): return False
 row=conn.execute('SELECT * FROM media WHERE directory_name=?',(folder.name,)).fetchone()
 if not row and serial:
  row=conn.execute('SELECT * FROM media WHERE volume_serial=?',(serial,)).fetchone()
 timestamp=now()
 if row:
  mid=row['id']
  if row['volume_serial'] and serial and row['volume_serial']!=serial: raise ValueError(f'{folder}: serial mismatch ({row["volume_serial"]} vs {serial}); aborting folder import')
  if row['directory_name'] != folder.name: raise ValueError(f'{folder}: existing serial is associated with {row["directory_name"]}; reconcile directories manually')
  conn.execute('UPDATE media SET barcode=COALESCE(?,barcode),volume_serial=COALESCE(volume_serial,?),generation=COALESCE(?,generation),archive_format=COALESCE(?,archive_format),backup_name=COALESCE(?,backup_name),catalog_path=COALESCE(?,catalog_path),updated_at_utc=? WHERE id=?',(bar,serial,gen,arch,name,str(catalog) if catalog else None,timestamp,mid))
 else:
  cur=conn.execute('INSERT INTO media(directory_name,barcode,volume_serial,generation,archive_format,backup_name,catalog_path,first_seen_utc,updated_at_utc) VALUES(?,?,?,?,?,?,?,?,?)',(folder.name,bar,serial,gen,arch,name,str(catalog) if catalog else None,ftime or timestamp,timestamp))
  mid=cur.lastrowid
 src=str(folder/'media-info.json')
 add_history(conn,mid,bar,'current',src)
 add_history(conn,mid,prev,'previous',src)
 if prev: event(conn,mid,'barcode_changed',{'from':prev,'to':bar,'date_exact':False},src,None)
 for td,m,r,h in entries:
  date=utc_from_stamp(td.name)
  dpath=td/'collected-at.txt'
  if dpath.is_file():
   try:
    raw_date=dpath.read_text().strip()
    date=dt.datetime.fromisoformat(raw_date.replace('Z','+00:00')).astimezone(dt.timezone.utc).isoformat(timespec='seconds')
   except (OSError,ValueError): pass
  if date is None: date=timestamp
  driveid=None
  if m.get('drive_serial'):
   conn.execute('INSERT INTO drives(serial,manufacturer,model,firmware) VALUES(?,?,?,?) ON CONFLICT(serial) DO UPDATE SET model=COALESCE(excluded.model,model),firmware=COALESCE(excluded.firmware,firmware)',(m['drive_serial'],'HP',m.get('drive_model'),m.get('drive_firmware')))
   driveid=conn.execute('SELECT id FROM drives WHERE serial=?',(m['drive_serial'],)).fetchone()[0]
  fields=['mounts','bop_passes','mop_passes','datasets_written','datasets_read','write_retries','read_retries','unrecovered_write_errors','unrecovered_read_errors','used_native_mb','total_native_mb','remaining_mib','max_capacity_mib','barcode_observed','volume_serial_observed','tape_alert_nonzero']
  query='INSERT INTO telemetry(media_id,collected_at_utc,snapshot_path,source_fingerprint,drive_id,'+','.join(fields)+',raw_files_json) VALUES('+','.join('?' for _ in range(6+len(fields)))+') ON CONFLICT(media_id,snapshot_path) DO UPDATE SET collected_at_utc=excluded.collected_at_utc,source_fingerprint=excluded.source_fingerprint,drive_id=excluded.drive_id,'+','.join(f'{f}=excluded.{f}' for f in fields)+',raw_files_json=excluded.raw_files_json'
  conn.execute(query,(mid,date,str(td),h,driveid,*[m.get(f) for f in fields],json.dumps(r,sort_keys=True)))
  add_history(conn,mid,m.get('barcode_observed'),'observed',str(td),date)
  if m.get('volume_serial_observed') and serial and m['volume_serial_observed']!=serial:
   raise ValueError(f'{td}: serial mismatch, data was not committed')
 if catalog:
  total,dirs,placeholder,restored,maxseq=catalog_info(catalog)
  cp=folder/'catalog'/'checkpoint.json';c=read_json(cp) if cp.is_file() else {}
  conn.execute('INSERT INTO catalogs(media_id,catalog_path,checkpoint_path,objects_total,directories,placeholders,restored,max_seq,checkpoint_offset,physical_block,catalog_mode,indexed_at_utc,observed_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(media_id,catalog_path) DO UPDATE SET checkpoint_path=excluded.checkpoint_path,objects_total=excluded.objects_total,directories=excluded.directories,placeholders=excluded.placeholders,restored=excluded.restored,max_seq=excluded.max_seq,checkpoint_offset=excluded.checkpoint_offset,physical_block=excluded.physical_block,catalog_mode=excluded.catalog_mode,observed_at_utc=excluded.observed_at_utc', (mid,str(catalog),str(cp) if cp.is_file() else None,total,dirs,placeholder,restored,maxseq,c.get('byte_offset'),c.get('physical_block'),c.get('mode'),None,timestamp))
 if catalog:
  extra=catalog_extra(catalog)
  conn.execute(
   """UPDATE catalogs
      SET files_total=?,size_known_files=?,size_known_bytes=?,
          tape_file_first=?,tape_file_last=?
      WHERE media_id=? AND catalog_path=?""",
   (*extra,mid,str(catalog))
  )
 return True

def scan(conn,root):
 if not root.is_dir(): raise ValueError(f'root does not exist: {root}')
 count=0
 for folder in sorted(root.iterdir()):
  if not folder.is_dir() or folder.is_symlink(): continue
  try:
   with conn:
    if scan_folder(conn,root,folder): count+=1; print(f'Imported: {folder.name}')
  except (ValueError,sqlite3.Error,OSError) as e: print(f'ERROR: {folder}: {e}',file=sys.stderr)
 print(f'Directories imported: {count}')

def list_media(conn):
 rows=conn.execute('''SELECT m.barcode,m.volume_serial,m.archive_format,
 (SELECT objects_total FROM catalogs c WHERE c.media_id=m.id ORDER BY c.id DESC LIMIT 1) objects,
 (SELECT mounts FROM telemetry t WHERE t.media_id=m.id ORDER BY t.collected_at_utc DESC LIMIT 1) mounts,
 m.directory_name FROM media m ORDER BY m.barcode,m.directory_name''').fetchall()
 print('BARCODE      VOLUME_SERIAL   FORMAT                    OBJECTS    MOUNTS  DIRECTORY')
 for r in rows: print(f'{r[0] or "-":12} {r[1] or "-":15} {(r[2] or "-")[:25]:25} {str(r[3] or "-"):>9} {str(r[4] if r[4] is not None else "-"):>8}  {r[5]}')

def get_media(conn,query):
 row=conn.execute('SELECT * FROM media WHERE barcode=? OR volume_serial=? OR directory_name=?',(query,query,query)).fetchone()
 if not row:
  row=conn.execute('SELECT m.* FROM media m JOIN barcode_history b ON b.media_id=m.id WHERE b.barcode=? LIMIT 1',(query,)).fetchone()
 if row is None: raise ValueError(f'unknown media: {query}')
 return row

def show(conn,query):
 row=get_media(conn,query); print(json.dumps(dict(row),ensure_ascii=False,indent=2))
 print('\nBarcode history:')
 for x in conn.execute('SELECT barcode,role,observed_at_utc,source FROM barcode_history WHERE media_id=? ORDER BY observed_at_utc',(row['id'],)): print('  ',dict(x))
 print('\nCatalogs:')
 for x in conn.execute('SELECT catalog_path,objects_total,directories,placeholders,restored,max_seq,checkpoint_offset FROM catalogs WHERE media_id=?',(row['id'],)): print('  ',dict(x))
 print('\nLatest telemetry:')
 x=conn.execute('SELECT * FROM telemetry WHERE media_id=? ORDER BY collected_at_utc DESC LIMIT 1',(row['id'],)).fetchone()
 if x: print(json.dumps({k:v for k,v in dict(x).items() if k not in ('raw_files_json',)},ensure_ascii=False,indent=2))

def history(conn,query):
 mid=get_media(conn,query)['id']
 for x in conn.execute('SELECT collected_at_utc,mounts,bop_passes,mop_passes,read_retries,write_retries,unrecovered_read_errors,unrecovered_write_errors,snapshot_path FROM telemetry WHERE media_id=? ORDER BY collected_at_utc',(mid,)): print(json.dumps(dict(x),ensure_ascii=False))
 for x in conn.execute('SELECT event_at_utc,type,details_json,source FROM events WHERE media_id=? ORDER BY event_at_utc',(mid,)): print(json.dumps(dict(x),ensure_ascii=False))

def export(conn,dest,kind):
 if kind not in ('media','telemetry','catalogs','barcode_history','events','drives'): raise ValueError('unsupported export table')
 data=conn.execute('SELECT * FROM '+kind); fields=[c[0] for c in data.description]
 with dest.open('w',newline='',encoding='utf-8-sig') as f:
  w=csv.writer(f);w.writerow(fields);w.writerows(data)
 print(f'Exported {kind} to {dest}')


def health(conn):
    """Display latest recorded tape health; no hardware access."""
    import json

    rows = conn.execute("""
        WITH latest AS (
            SELECT *,
                   ROW_NUMBER() OVER (
                       PARTITION BY media_id
                       ORDER BY collected_at_utc DESC, id DESC
                   ) AS rn
            FROM telemetry
        )
        SELECT m.barcode, m.generation,
               t.mounts, t.bop_passes, t.mop_passes,
               t.read_retries, t.write_retries,
               t.unrecovered_read_errors AS rfail,
               t.unrecovered_write_errors AS wfail,
               t.used_native_mb, t.total_native_mb,
               t.tape_alert_nonzero, t.collected_at_utc
        FROM media m
        LEFT JOIN latest t
          ON t.media_id=m.id AND t.rn=1
        ORDER BY m.barcode
    """).fetchall()

    headers = [
        'Barcode', 'LTO', 'Mounts', 'BOP', 'MOP',
        'RRetry', 'WRetry', 'RFail', 'WFail',
        'Used%', 'Health', 'Collected'
    ]

    results = []

    for r in rows:
        barcode, generation, mounts, bop, mop, rr, wr, rf, wf, used, total, alert_raw, collected = r

        if collected is None:
            status = 'UNKNOWN'
        elif rf is None or wf is None:
            status = 'UNKNOWN'
        elif rf > 0 or wf > 0:
            status = 'CRITICAL'
        else:
            try:
                alerts = json.loads(alert_raw or '{}')
                if not isinstance(alerts, dict):
                    status = 'UNKNOWN'
                elif any(str(v).strip().lower() not in
                         ('0', 'false', 'none', 'null', '')
                         for v in alerts.values()):
                    status = 'WARNING'
                else:
                    status = 'OK'
            except (ValueError, TypeError):
                status = 'UNKNOWN'

        used_pct = (
            f'{used / total * 100:.1f}'
            if used is not None and total
            else '-'
        )

        results.append([
            barcode, generation, mounts, bop, mop,
            rr, wr, rf, wf, used_pct, status, collected
        ])

    widths = [
        max(len(str(x if x is not None else '-'))
            for x in [header] + [row[i] for row in results])
        for i, header in enumerate(headers)
    ]

    def display(row):
        return '  '.join(
            str(value if value is not None else '-').ljust(widths[i])
            for i, value in enumerate(row)
        )

    print(display(headers))
    print('  '.join('-' * width for width in widths))
    for row in results:
        print(display(row))

def main():
 p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
 p.add_argument('--root',type=Path,default=DEFAULT_ROOT)
 p.add_argument('--db',type=Path,default=None)
 sub=p.add_subparsers(dest='command',required=True)
 for cmd in ('init','scan','list','health'): sub.add_parser(cmd)
 for cmd in ('show','history'): sub.add_parser(cmd).add_argument('media')
 ep=sub.add_parser('export');ep.add_argument('table',choices=['media','telemetry','catalogs','barcode_history','events','drives']);ep.add_argument('output',type=Path)
 a=p.parse_args();database=a.db or a.root/'tape-inventory.sqlite3'
 try:
  with db_connect(database) as conn:
   if a.command=='init': print('Created:',database)
   elif a.command=='scan': scan(conn,a.root)
   elif a.command=='list': list_media(conn)
   elif a.command=='health': health(conn)
   elif a.command=='show': show(conn,a.media)
   elif a.command=='history': history(conn,a.media)
   elif a.command=='export': export(conn,a.output,a.table)
 except (ValueError,RuntimeError,sqlite3.Error,OSError) as e:
  print(f'ERROR: {e}',file=sys.stderr);return 1
 return 0

if __name__=='__main__': sys.exit(main())


def health_report(db_path):
    """Print media health from the latest saved telemetry."""
    import sqlite3
    import json

    db = sqlite3.connect(str(db_path))
    db.row_factory = sqlite3.Row

    rows = db.execute("""
        WITH latest AS (
            SELECT *,
                   ROW_NUMBER() OVER (
                       PARTITION BY media_id
                       ORDER BY collected_at_utc DESC, id DESC
                   ) AS rn
            FROM telemetry
        )
        SELECT m.barcode, m.generation,
               t.mounts, t.bop_passes, t.mop_passes,
               t.read_retries, t.write_retries,
               t.unrecovered_read_errors AS rfail,
               t.unrecovered_write_errors AS wfail,
               t.used_native_mb, t.total_native_mb,
               t.tape_alert_nonzero, t.collected_at_utc
        FROM media m
        LEFT JOIN latest t ON t.media_id=m.id AND t.rn=1
        ORDER BY m.barcode
    """).fetchall()
    db.close()

    headers = [
        'Barcode', 'LTO', 'Mounts', 'BOP', 'MOP',
        'RRetry', 'WRetry', 'RFail', 'WFail',
        'Used%', 'Health', 'Collected'
    ]

    result = []
    for r in rows:
        alerts = {}
        if r['tape_alert_nonzero']:
            try:
                alerts = json.loads(r['tape_alert_nonzero'])
            except (ValueError, TypeError):
                alerts = {'parse_error': True}

        failures = (r['rfail'] or 0) + (r['wfail'] or 0)

        if r['collected_at_utc'] is None:
            status = 'UNKNOWN'
        elif failures:
            status = 'CRITICAL'
        elif alerts:
            status = 'WARNING'
        elif r['rfail'] is None or r['wfail'] is None:
            status = 'UNKNOWN'
        else:
            status = 'OK'

        used = (
            round(100 * r['used_native_mb'] / r['total_native_mb'], 1)
            if r['used_native_mb'] is not None and r['total_native_mb']
            else None
        )

        result.append([
            r['barcode'], r['generation'], r['mounts'],
            r['bop_passes'], r['mop_passes'],
            r['read_retries'], r['write_retries'],
            r['rfail'], r['wfail'], used,
            status, r['collected_at_utc']
        ])

    widths = [
        max(len(str(v if v is not None else '-')) for v in [h] + [
            row[i] for row in result
        ])
        for i, h in enumerate(headers)
    ]

    for row in [headers] + result:
        print('  '.join(
            str(v if v is not None else '-').ljust(widths[i])
            for i, v in enumerate(row)
        ))
