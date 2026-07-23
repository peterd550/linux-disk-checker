# linux-disk-checker

`linux-disk-checker` is a read-only disk and mount health inspection tool for Linux.

It inspects one mount or all mounted disks, then generates:

- JSON output for automation and pipelines
- HTML output for human-readable reporting

The tool does **not** create, modify, or delete files on the target mount(s).

## Why This Exists

Traditional disk checks are often either:

- too low-level and hard to read quickly, or
- too shallow and missing useful context.

This project provides a structured, report-oriented middle ground:

- mount and filesystem context
- capacity and inode pressure analysis
- permission and traversal diagnostics
- read-path sampling from existing files
- clear `passed` / `warning` / `failed` outcome semantics

## What It Tests

The script runs these read-only test groups:

1. `mount_health`
- Resolves requested target to a mount directory.
- Detects device, filesystem type, mountpoint, and mount options.
- Flags mount-option anomalies when detection is incomplete.

2. `capacity_and_inodes`
- Calculates disk usage percent.
- Calculates inode usage percent.
- Applies warn/fail thresholds for both.

3. `directory_traversal`
- Walks the directory tree up to `--max-walk-entries`.
- Counts directories, files, and total entries seen.
- Reports permission-denied and traversal access issues.

4. `file_read_sample`
- Selects up to `--sample-files` existing files.
- Reads up to `--sample-read-bytes` from each.
- Reports read latency and any read failures.

## Read-Only Guarantee

On the tested mount(s), this tool:

- does not write files
- does not create directories
- does not delete files

It only reads metadata and file content samples.

Important:

- Report files are written to `--output-dir` (default: `./reports`).
- If `--output-dir` is inside a tested mount, that output path will be written as expected.

## Requirements

- Linux
- Python 3.10+

No third-party dependencies are required.

## Install / Run

Run directly:

```bash
python3 disk_checker.py --mount /
```

## Mount Input Modes

`--mount` supports three modes:

1. Mount directory

```bash
python3 disk_checker.py --mount /mnt/hdd/disk1
```

2. Device path

```bash
python3 disk_checker.py --mount /dev/sda1
```

If a device is mounted, it is automatically resolved to its mount directory.

3. All mounted disks

```bash
python3 disk_checker.py --mount all
```

This runs the suite for each discovered mounted disk and produces:

- one aggregate report
- one report pair per mount

## How `--mount all` Discovery Works

The script discovers mounts from `/proc/mounts` and includes targets that are:

- backed by `/dev/*`
- directory mountpoints that exist
- readable and traversable by the current user

It skips pseudo/transient filesystems and non-disk style entries.

## Command Reference

```text
--mount                Required. Mount directory, mounted device path, or all.
--output-dir           Report output directory. Default: ./reports
--run-label            Optional tag embedded in run IDs. Default: readonly
--allow-non-mount      Allow directory input that is not a true mountpoint.
--sample-files         Max files to sample read in file_read_sample. Default: 50
--sample-read-bytes    Bytes read per sampled file. Default: 1048576
--max-walk-entries     Traversal cap for very large filesystems. Default: 50000
--usage-warn-percent   Disk usage warning threshold. Default: 85
--usage-fail-percent   Disk usage fail threshold. Default: 95
--inode-warn-percent   Inode usage warning threshold. Default: 85
--inode-fail-percent   Inode usage fail threshold. Default: 95
--verbose              Enable verbose logging.
```

## Practical Examples

Single mounted device (read-only checks):

```bash
python3 disk_checker.py \
	--mount /dev/sda1 \
	--output-dir ./reports
```

Fast smoke test:

```bash
python3 disk_checker.py \
	--mount / \
	--output-dir ./reports \
	--max-walk-entries 2000 \
	--sample-files 5 \
	--sample-read-bytes 32768
```

All mounted disks:

```bash
python3 disk_checker.py \
	--mount all \
	--output-dir ./reports
```

Stricter thresholds:

```bash
python3 disk_checker.py \
	--mount /data \
	--usage-warn-percent 75 \
	--usage-fail-percent 90 \
	--inode-warn-percent 70 \
	--inode-fail-percent 85
```

## Output Files

Each single-mount run writes:

- `<run-id>.json`
- `<run-id>.html`

`--mount all` writes:

- one aggregate `<run-id>-all-*.json`
- one aggregate `<run-id>-all-*.html`
- per-mount JSON/HTML reports for each discovered mount

## Exit Codes

- `0`: overall status `passed`
- `1`: overall status `warning`
- `2`: overall status `failed`
- `3`: validation/configuration error
- `99`: unexpected internal error
- `130`: interrupted by user (`Ctrl+C`)

If you see exit code `1`, the run completed successfully but found non-fatal warnings.

## Interpreting Status

Each test and overall run has one of:

- `passed`: no issues detected for that scope
- `warning`: issues detected that may need attention
- `failed`: serious issue or test failure

Typical warning causes:

- high disk usage above warning threshold
- high inode usage above warning threshold
- permission-denied paths during traversal
- some sampled files not readable

Typical failed causes:

- disk/inode usage above fail threshold
- all sampled files failed to read
- unexpected runtime error in a test block

## Report Structure

JSON contains:

- run metadata (id, timestamps, duration, status)
- effective config values
- system snapshot
- test results with metrics and warnings

HTML contains:

- summary KPIs and status
- environment and mount details
- metric tables
- warnings and errors
- full effective config dump

## Limitations

- This is a filesystem-level health inspector, not a hardware diagnostic tool.
- It does not run SMART/NVMe firmware health checks.
- It does not perform write stress tests by design.
- Read sampling depends on what files are visible and readable for the current user.

## Troubleshooting

`Validation error: Mount path is not a directory`
- You likely passed a device that is not mounted, or an invalid path.
- Confirm with `lsblk -f` or `mount` and retry.

`Validation error: Mount path does not exist`
- Confirm mount is currently active.
- If path has spaces, quote it.

Exit code `1` with `--mount all`
- At least one mount produced warnings.
- Open aggregate HTML report first, then inspect linked per-mount reports.

Permission warnings
- Re-run with a user that has read/traverse access to more paths.

## Development Notes

- Main script: `disk_checker.py`
- Reports directory: `reports/`
- Generated report files are ignored by `.gitignore`