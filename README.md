# LTO Tape Recovery Scripts

A vibe-coded collection of Python scripts for recovering data from proprietary LTO tape backup formats, including Proxmox Backup Server (PBS), DIVA, and Yosemite Server Backup.

These tools are designed for disaster recovery, data extraction, and archive inspection without requiring the original backup software.

**Disclaimer:** These scripts are experimental, AI-assisted, and developed through reverse engineering and real-world testing. Always verify recovered data and preserve original tapes.

## Supported Backup Formats

| Backup system | Physical LTO tapes | Raw tape images | Recovery capabilities |
|---|---|---|---|
| **Proxmox Backup Server (PBS)** | Experimental | Tested | Datastore discovery, chunk and snapshot restoration |
| **DIVA** | Supported | Not verified | Archive catalog scanning and selective object recovery |
| **Yosemite Server Backup** | Experimental | Supported by selected tools | Archive indexing and individual/batch file recovery |

The tools operate on backup formats, not specific tape generations. LTO-6 has been used during development. Other LTO generations may work with compatible Linux SCSI tape drives but have not been verified.

**Important:** These are experimental disaster-recovery utilities. Always retain the original tapes and verify recovered data.

## Requirements

- Linux with Python 3
- SCSI tape drive supported by the Linux `st` driver
- `mt-st` and `mtx` for physical tape access
- Sufficient disk space for recovered files and temporary buffers
- `pxar` for PBS snapshot extraction
- Initialized PBS datastore for PBS restoration

Default device paths:

- `/dev/nst0` — non-rewinding tape device
- `/dev/sg3` — tape changer

Device paths may differ between systems.

## Tools

### Proxmox Backup Server

| Script | Purpose |
|---|---|
| `pbs_tape_rescue.py` | Capture physical tape files into raw disk images |
| `pbs_tape_restore.py` | Discover source datastores and restore PBS backups from tape or saved images |

The restore tool supports chunk archives, snapshot archives, automatic end-of-data detection and PBS backup-group ownership metadata.

### DIVA

| Script | Purpose |
|---|---|
| `diva_catalog_scan.py` | Scan DIVA tape metadata and build a recovery catalog |
| `diva_restore_one.py` | Selectively restore archived objects using catalog information |

### Yosemite Server Backup

| Script | Purpose |
|---|---|
| `yosemite_recover.py` | Scan and index Yosemite archive objects |
| `yosemite_parser.py` | Compatibility parser for indexed recovery |
| `yosemite_restore_one.py` | Restore individual archived objects |
| `yosemite_restore_batch.py` | Restore multiple indexed objects |

## Usage Examples

### 1. PBS — Discover datastores on an LTO tape

```bash
mkdir -p /root/tape-recovery/X00123L6/tmp

python3 pbs_tape_restore.py \
  --tape /dev/nst0 \
  --changer /dev/sg3 \
  --barcode X00123L6 \
  --scratch /root/tape-recovery/X00123L6/tmp \
  --list-stores
```

The script reads tape metadata and reports the source datastore names and available snapshots without modifying a datastore.

When `--last-file` is omitted, tape reading continues until end-of-data detection.

### 2. PBS — Capture a tape to disk

```bash
python3 pbs_tape_rescue.py \
  --tape /dev/nst0 \
  --changer /dev/sg3 \
  --barcode X00123L6 \
  --out /root/tape-recovery/X00123L6/raw \
  --first-file 0 \
  --last-file 10
```

Creates `file-000000.bin`, `file-000001.bin`, etc., and a `manifest.json` containing file metadata and SHA-256 checksums.

Unlike the restore tool, this acquisition script requires a known `--last-file`.

### 3. PBS — Restore directly from LTO

```bash
python3 pbs_tape_restore.py \
  --tape /dev/nst0 \
  --changer /dev/sg3 \
  --barcode X00123L6 \
  --scratch /root/tape-recovery/X00123L6/tmp \
  --source-store tape-test \
  --datastore-path /mnt/datastore/tape-restore-test \
  --restore
```

The destination must already be an initialized PBS datastore.

The default backup owner is `root@pam`. Use `--backup-owner` to override it.

Temporary tape data is buffered under `--scratch` and processed one tape file at a time.

### 4. PBS — Restore from previously captured raw files

```bash
python3 pbs_tape_restore.py \
  --raw /root/tape-recovery/X00123L6/raw \
  --source-store tape-test \
  --datastore-path /mnt/datastore/tape-restore-test \
  --restore
```

This mode does not access the physical tape drive.

### 5. PBS — Verify restored backups

```bash
proxmox-backup-manager verify tape-restore-test \
  --ignore-verified false
```

Successful verification should end with `TASK OK` and zero errors.

Restoration from raw tape captures has been successfully verified against real PBS backups, including restoration into empty and populated datastores.

### 6. DIVA — Scan and restore archived objects

Inspect the scanner's available parameters:

```bash
python3 diva_catalog_scan.py --help
```

List matching catalog objects:

```bash
python3 diva_restore_one.py \
  --db /root/tape-recovery/X00123L6/catalog/catalog.sqlite3 \
  --list \
  --name FILENAME
```

Restore selected objects:

```bash
python3 diva_restore_one.py \
  --db /root/tape-recovery/X00123L6/catalog/catalog.sqlite3 \
  --id 1,2
```

DIVA recovery depends on accurate catalog information and the correct source tape.

### 7. Yosemite — Index and restore archived files

Inspect available indexing options:

```bash
python3 yosemite_recover.py --help
```

List indexed files:

```bash
python3 yosemite_restore_batch.py \
  --db /path/to/catalog.sqlite3 \
  --list
```

The Yosemite tools support indexed recovery using archive record offsets. Some operations can read captured data instead of a physical tape.

Always verify the tape barcode and ensure that catalog offsets correspond to the same cartridge and record layout.

## Safety and Limitations

- Physical tapes are opened for reading only.
- Recovery does not require the original DIVA or Yosemite backup application.
- PBS recovery does not require the PBS Tape Restore API, but needs compatible PBS datastore structures and `pxar`.
- Previously captured images can be used without tape hardware where supported.
- Unknown archive formats, encrypted payloads and incomplete media may not be recoverable.
- Automatic EOD handling and physical tape recovery require additional hardware testing.
- Never overwrite valuable restored data without independent verification.

## Validation

PBS restoration has been tested using an LTO-6 tape capture containing three container snapshots. All snapshots were recognized by PBS and passed full datastore verification with zero errors.

DIVA and Yosemite utilities are format-specific recovery tools; their recovery coverage and reliability depend on the available media, catalog metadata and archive structure.

## Disclaimer

This project is experimental and is not affiliated with or endorsed by Proxmox, DIVA or Yosemite vendors. Use at your own risk. Keep original media unchanged and verify recovered files before relying on them.
