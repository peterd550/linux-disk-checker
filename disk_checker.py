#!/usr/bin/env python3
"""Read-only disk mount health checker with HTML/JSON reporting.

This tool inspects a target mount path without modifying files on that mount.
It performs filesystem and read-path diagnostics and reports findings.
"""

from __future__ import annotations

import argparse
import codecs
import json
import logging
import math
import os
import platform
import shutil
import signal
import socket
import statistics
import sys
import threading
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


LOGGER = logging.getLogger("disk_checker")


class GracefulInterrupt:
    """Tracks SIGINT/SIGTERM for cooperative shutdown."""

    def __init__(self) -> None:
        self._event = threading.Event()
        signal.signal(signal.SIGINT, self._handler)
        signal.signal(signal.SIGTERM, self._handler)

    def _handler(self, signum: int, _frame: Any) -> None:
        LOGGER.warning("Received signal %s, finishing current operation then exiting.", signum)
        self._event.set()

    @property
    def requested(self) -> bool:
        return self._event.is_set()


@dataclass
class HealthPolicy:
    usage_warn_percent: float
    usage_fail_percent: float
    inode_warn_percent: float
    inode_fail_percent: float


@dataclass
class AppConfig:
    mount_input: str
    mount: Path
    output_dir: Path
    run_label: str
    allow_non_mount: bool
    sample_files: int
    sample_read_bytes: int
    max_walk_entries: int
    policy: HealthPolicy


@dataclass
class MetricStats:
    unit: str
    count: int
    minimum: float
    maximum: float
    mean: float
    median: float
    p95: float
    stddev: float


@dataclass
class TestResult:
    name: str
    status: str
    started_at: str
    ended_at: str
    duration_s: float
    metrics: Dict[str, MetricStats] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class MountDetails:
    requested_path: str
    resolved_path: str
    mountpoint: str
    is_mountpoint: bool
    fs_type: str
    device: str
    mount_options: List[str]


@dataclass
class SystemSnapshot:
    hostname: str
    platform: str
    python: str
    cpu_count: int
    load_avg: Optional[Tuple[float, float, float]]
    disk_total_bytes: int
    disk_used_bytes: int
    disk_free_bytes: int
    inode_total: int
    inode_free: int
    mount: MountDetails


@dataclass
class RunReport:
    run_id: str
    started_at: str
    ended_at: str
    duration_s: float
    status: str
    config: Dict[str, Any]
    system: SystemSnapshot
    tests: List[TestResult]
    warnings: List[str]


@dataclass
class ExecutionContext:
    config: AppConfig
    interrupt: GracefulInterrupt


@dataclass
class AggregateRunSummary:
    run_id: str
    started_at: str
    ended_at: str
    duration_s: float
    status: str
    mount_input: str
    mount_count: int
    config: Dict[str, Any]
    runs: List[Dict[str, Any]]
    warnings: List[str]


class DiskCheckError(Exception):
    pass


class DiskTest:
    name = "base"

    def run(self, context: ExecutionContext) -> TestResult:
        raise NotImplementedError


IGNORED_FS_TYPES = {
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "nsfs",
    "overlay",
    "proc",
    "pstore",
    "ramfs",
    "rpc_pipefs",
    "securityfs",
    "squashfs",
    "sysfs",
    "tmpfs",
    "tracefs",
}


def utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def percentile(values: Sequence[float], q: float) -> float:
    if not values:
        raise ValueError("Cannot calculate percentile of empty sequence")
    if len(values) == 1:
        return values[0]
    sorted_values = sorted(values)
    k = (len(sorted_values) - 1) * q
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_values[int(k)]
    d0 = sorted_values[f] * (c - k)
    d1 = sorted_values[c] * (k - f)
    return d0 + d1


def to_stats(values: Sequence[float], unit: str) -> MetricStats:
    if not values:
        return MetricStats(unit=unit, count=0, minimum=0.0, maximum=0.0, mean=0.0, median=0.0, p95=0.0, stddev=0.0)
    return MetricStats(
        unit=unit,
        count=len(values),
        minimum=min(values),
        maximum=max(values),
        mean=statistics.mean(values),
        median=statistics.median(values),
        p95=percentile(values, 0.95),
        stddev=statistics.stdev(values) if len(values) > 1 else 0.0,
    )


def decode_mount_field(value: str) -> str:
    """Decode escaped mount fields used in /proc/mounts (e.g. \040 for space)."""
    try:
        return codecs.decode(value, "unicode_escape")
    except Exception:  # pylint: disable=broad-except
        return value


def find_mount_info(path: Path) -> MountDetails:
    requested = str(path)
    resolved = str(path.resolve())
    best_mountpoint = ""
    best_dev = "unknown"
    best_fs_type = "unknown"
    best_options: List[str] = []

    try:
        with open("/proc/mounts", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 4:
                    continue
                dev = decode_mount_field(parts[0])
                mountpoint = decode_mount_field(parts[1])
                fs_type, options = parts[2], parts[3]
                if resolved.startswith(mountpoint.rstrip("/") + "/") or resolved == mountpoint:
                    if len(mountpoint) >= len(best_mountpoint):
                        best_mountpoint = mountpoint
                        best_dev = dev
                        best_fs_type = fs_type
                        best_options = options.split(",")
    except OSError:
        LOGGER.exception("Failed reading /proc/mounts")

    is_mount = os.path.ismount(resolved)
    return MountDetails(
        requested_path=requested,
        resolved_path=resolved,
        mountpoint=best_mountpoint,
        is_mountpoint=is_mount,
        fs_type=best_fs_type,
        device=best_dev,
        mount_options=best_options,
    )


def resolve_mount_argument(mount_arg: str) -> Path:
    """Resolve either a mount directory or a mounted device path to a directory.

    Examples:
    - /media/user/disk -> /media/user/disk
    - /dev/sda1 -> /media/user/disk (if mounted)
    """
    candidate = Path(mount_arg).expanduser()
    if candidate.exists() and candidate.is_dir():
        return candidate

    try:
        resolved_arg = str(candidate.resolve()) if candidate.exists() else str(candidate)
    except OSError:
        resolved_arg = str(candidate)

    try:
        with open("/proc/mounts", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 2:
                    continue
                dev = decode_mount_field(parts[0])
                mnt = decode_mount_field(parts[1])
                if dev == mount_arg or dev == resolved_arg:
                    return Path(mnt)
    except OSError:
        LOGGER.exception("Failed reading /proc/mounts while resolving mount argument")

    return candidate


def collect_system_snapshot(config: AppConfig, mount_info: MountDetails) -> SystemSnapshot:
    usage = shutil.disk_usage(config.mount)
    st = os.statvfs(config.mount)

    try:
        load_avg = os.getloadavg()
    except OSError:
        load_avg = None

    inode_total = st.f_files if st.f_files >= 0 else 0
    inode_free = st.f_ffree if st.f_ffree >= 0 else 0

    return SystemSnapshot(
        hostname=socket.gethostname(),
        platform=platform.platform(),
        python=sys.version.replace("\n", " "),
        cpu_count=os.cpu_count() or 1,
        load_avg=load_avg,
        disk_total_bytes=usage.total,
        disk_used_bytes=usage.used,
        disk_free_bytes=usage.free,
        inode_total=inode_total,
        inode_free=inode_free,
        mount=mount_info,
    )


class MountHealthTest(DiskTest):
    name = "mount_health"

    def run(self, context: ExecutionContext) -> TestResult:
        started = utc_now()
        t0 = time.perf_counter()
        warnings: List[str] = []

        try:
            info = find_mount_info(context.config.mount)
            opts = set(info.mount_options)

            if "ro" in opts:
                warnings.append("Filesystem is mounted read-only")
            if "errors=remount-ro" in opts:
                warnings.append("Mount uses errors=remount-ro; monitor logs for filesystem errors")
            if not info.mount_options:
                warnings.append("Mount options could not be detected from /proc/mounts")

            details = {
                "requested_path": info.requested_path,
                "resolved_path": info.resolved_path,
                "detected_mountpoint": info.mountpoint,
                "device": info.device,
                "fs_type": info.fs_type,
                "mount_options": info.mount_options,
            }
            status = "warning" if warnings else "passed"
            error = None
            metrics: Dict[str, MetricStats] = {}
        except Exception as exc:  # pylint: disable=broad-except
            details = {"traceback": traceback.format_exc()}
            status = "failed"
            error = f"{type(exc).__name__}: {exc}"
            metrics = {}

        t1 = time.perf_counter()
        return TestResult(
            name=self.name,
            status=status,
            started_at=started,
            ended_at=utc_now(),
            duration_s=t1 - t0,
            metrics=metrics,
            details=details,
            warnings=warnings,
            error=error,
        )


class CapacityAndInodeTest(DiskTest):
    name = "capacity_and_inodes"

    def run(self, context: ExecutionContext) -> TestResult:
        started = utc_now()
        t0 = time.perf_counter()
        warnings: List[str] = []

        try:
            usage = shutil.disk_usage(context.config.mount)
            st = os.statvfs(context.config.mount)

            used_pct = (usage.used / usage.total) * 100 if usage.total else 0.0
            inode_used_pct = 0.0
            if st.f_files > 0:
                inode_used_pct = ((st.f_files - st.f_ffree) / st.f_files) * 100

            policy = context.config.policy
            status = "passed"

            if used_pct >= policy.usage_fail_percent:
                status = "failed"
                warnings.append(
                    f"Disk usage critical: {used_pct:.2f}% >= fail threshold {policy.usage_fail_percent:.2f}%"
                )
            elif used_pct >= policy.usage_warn_percent:
                status = "warning"
                warnings.append(
                    f"Disk usage high: {used_pct:.2f}% >= warn threshold {policy.usage_warn_percent:.2f}%"
                )

            if inode_used_pct >= policy.inode_fail_percent:
                status = "failed"
                warnings.append(
                    f"Inode usage critical: {inode_used_pct:.2f}% >= fail threshold {policy.inode_fail_percent:.2f}%"
                )
            elif inode_used_pct >= policy.inode_warn_percent and status != "failed":
                status = "warning"
                warnings.append(
                    f"Inode usage high: {inode_used_pct:.2f}% >= warn threshold {policy.inode_warn_percent:.2f}%"
                )

            metrics = {
                "disk_used_percent": to_stats([used_pct], "%"),
                "inode_used_percent": to_stats([inode_used_pct], "%"),
            }
            details = {
                "disk_total_bytes": usage.total,
                "disk_used_bytes": usage.used,
                "disk_free_bytes": usage.free,
                "inode_total": st.f_files,
                "inode_free": st.f_ffree,
            }
            error = None
        except Exception as exc:  # pylint: disable=broad-except
            status = "failed"
            metrics = {}
            details = {"traceback": traceback.format_exc()}
            error = f"{type(exc).__name__}: {exc}"

        t1 = time.perf_counter()
        return TestResult(
            name=self.name,
            status=status,
            started_at=started,
            ended_at=utc_now(),
            duration_s=t1 - t0,
            metrics=metrics,
            details=details,
            warnings=warnings,
            error=error,
        )


class DirectoryTraversalTest(DiskTest):
    name = "directory_traversal"

    def run(self, context: ExecutionContext) -> TestResult:
        started = utc_now()
        t0 = time.perf_counter()
        warnings: List[str] = []

        dirs_seen = 0
        files_seen = 0
        permission_errors = 0
        entries_seen = 0

        try:
            for root, dirnames, filenames in os.walk(context.config.mount, topdown=True, followlinks=False):
                if context.interrupt.requested:
                    raise KeyboardInterrupt("Interrupted by user")

                dirs_seen += 1
                files_seen += len(filenames)
                entries_seen += len(dirnames) + len(filenames)

                # Bound work so large filesystems remain practical for routine checks.
                if entries_seen >= context.config.max_walk_entries:
                    warnings.append(
                        f"Traversal stopped after {entries_seen} entries (max_walk_entries reached)"
                    )
                    break

                # Probe directory readability without opening files.
                try:
                    _ = os.listdir(root)
                except PermissionError:
                    permission_errors += 1
                except OSError as exc:
                    warnings.append(f"Traversal warning in {root}: {exc}")

            status = "passed"
            if permission_errors > 0:
                status = "warning"
                warnings.append(f"Permission denied on {permission_errors} directories during traversal")

            metrics = {
                "directories_seen": to_stats([float(dirs_seen)], "count"),
                "files_seen": to_stats([float(files_seen)], "count"),
                "entries_seen": to_stats([float(entries_seen)], "count"),
                "permission_denied_count": to_stats([float(permission_errors)], "count"),
            }
            details = {
                "max_walk_entries": context.config.max_walk_entries,
                "directories_seen": dirs_seen,
                "files_seen": files_seen,
                "entries_seen": entries_seen,
                "permission_errors": permission_errors,
            }
            error = None
        except Exception as exc:  # pylint: disable=broad-except
            status = "failed"
            metrics = {}
            details = {"traceback": traceback.format_exc()}
            error = f"{type(exc).__name__}: {exc}"

        t1 = time.perf_counter()
        return TestResult(
            name=self.name,
            status=status,
            started_at=started,
            ended_at=utc_now(),
            duration_s=t1 - t0,
            metrics=metrics,
            details=details,
            warnings=warnings,
            error=error,
        )


class FileReadSampleTest(DiskTest):
    name = "file_read_sample"

    def run(self, context: ExecutionContext) -> TestResult:
        started = utc_now()
        t0 = time.perf_counter()
        warnings: List[str] = []

        sample_targets: List[Path] = []
        read_latency_ms: List[float] = []
        read_bytes: List[float] = []
        read_failures = 0

        try:
            for root, _dirs, filenames in os.walk(context.config.mount, topdown=True, followlinks=False):
                for name in filenames:
                    p = Path(root) / name
                    if not p.is_file():
                        continue
                    sample_targets.append(p)
                    if len(sample_targets) >= context.config.sample_files:
                        break
                if len(sample_targets) >= context.config.sample_files:
                    break

            if not sample_targets:
                warnings.append("No readable files discovered for sample read test")
                status = "warning"
                metrics = {}
                details = {
                    "sample_files_requested": context.config.sample_files,
                    "sample_files_selected": 0,
                }
                error = None
            else:
                for p in sample_targets:
                    if context.interrupt.requested:
                        raise KeyboardInterrupt("Interrupted by user")
                    try:
                        start = time.perf_counter()
                        with open(p, "rb") as fh:
                            data = fh.read(context.config.sample_read_bytes)
                        end = time.perf_counter()
                        read_latency_ms.append((end - start) * 1000)
                        read_bytes.append(float(len(data)))
                    except (OSError, PermissionError):
                        read_failures += 1

                if read_failures == len(sample_targets):
                    status = "failed"
                    warnings.append("All sampled files failed to read")
                elif read_failures > 0:
                    status = "warning"
                    warnings.append(f"{read_failures} sampled files failed to read")
                else:
                    status = "passed"

                metrics = {
                    "sample_read_latency_ms": to_stats(read_latency_ms, "ms"),
                    "sample_read_bytes": to_stats(read_bytes, "bytes"),
                    "sample_read_failures": to_stats([float(read_failures)], "count"),
                }
                details = {
                    "sample_files_requested": context.config.sample_files,
                    "sample_files_selected": len(sample_targets),
                    "sample_read_bytes_per_file": context.config.sample_read_bytes,
                    "sampled_paths": [str(p) for p in sample_targets[:20]],
                    "sampled_paths_truncated": len(sample_targets) > 20,
                    "read_failures": read_failures,
                }
                error = None
        except Exception as exc:  # pylint: disable=broad-except
            status = "failed"
            metrics = {}
            details = {"traceback": traceback.format_exc()}
            error = f"{type(exc).__name__}: {exc}"

        t1 = time.perf_counter()
        return TestResult(
            name=self.name,
            status=status,
            started_at=started,
            ended_at=utc_now(),
            duration_s=t1 - t0,
            metrics=metrics,
            details=details,
            warnings=warnings,
            error=error,
        )


def render_html(report: RunReport) -> str:
    tests_html: List[str] = []

    for test in report.tests:
        metric_rows = []
        for metric_name, metric in test.metrics.items():
            metric_rows.append(
                """
                <tr>
                    <td>{name}</td>
                    <td>{unit}</td>
                    <td>{count}</td>
                    <td>{minimum:.4f}</td>
                    <td>{maximum:.4f}</td>
                    <td>{mean:.4f}</td>
                    <td>{median:.4f}</td>
                    <td>{p95:.4f}</td>
                    <td>{stddev:.4f}</td>
                </tr>
                """.format(
                    name=metric_name,
                    unit=metric.unit,
                    count=metric.count,
                    minimum=metric.minimum,
                    maximum=metric.maximum,
                    mean=metric.mean,
                    median=metric.median,
                    p95=metric.p95,
                    stddev=metric.stddev,
                )
            )

        details_json = json.dumps(test.details, indent=2)
        warnings_html = "".join(f"<li>{w}</li>" for w in test.warnings) or "<li>None</li>"

        tests_html.append(
            f"""
            <section class=\"card\">
                <h2>{test.name}</h2>
                <p><strong>Status:</strong> <span class=\"status {test.status}\">{test.status.upper()}</span></p>
                <p><strong>Duration:</strong> {test.duration_s:.2f}s</p>
                <p><strong>Started:</strong> {test.started_at}<br><strong>Ended:</strong> {test.ended_at}</p>
                {f'<p class="error"><strong>Error:</strong> {test.error}</p>' if test.error else ''}
                <h3>Metrics</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Name</th><th>Unit</th><th>N</th><th>Min</th><th>Max</th><th>Mean</th><th>Median</th><th>P95</th><th>StdDev</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(metric_rows) if metric_rows else '<tr><td colspan="9">No metrics</td></tr>'}
                    </tbody>
                </table>
                <h3>Warnings</h3>
                <ul>{warnings_html}</ul>
                <h3>Details</h3>
                <pre>{details_json}</pre>
            </section>
            """
        )

    load_avg_text = "N/A" if report.system.load_avg is None else ", ".join(f"{x:.2f}" for x in report.system.load_avg)

    style = """
    :root {
        --bg: #f4f7f1;
        --panel: #ffffff;
        --ink: #122117;
        --soft: #5f6f61;
        --ok: #1f8a4c;
        --warn: #b36b00;
        --bad: #b02020;
        --grid: #d8e2d6;
        --accent: #0e6b5c;
    }
    body {
        font-family: "IBM Plex Sans", "DejaVu Sans", sans-serif;
        margin: 0;
        color: var(--ink);
        background: radial-gradient(circle at 10% 5%, #e7f3e9 0%, var(--bg) 55%);
    }
    header {
        padding: 28px;
        background: linear-gradient(120deg, #cbe6d3 0%, #d9f0e2 40%, #f3f9ef 100%);
        border-bottom: 1px solid #c3d9c7;
    }
    .report-title {
        font-family: "Payaya", "Papyrus", "Comic Sans MS", cursive;
        letter-spacing: 0.02em;
    }
    main { padding: 24px; max-width: 1200px; margin: 0 auto; }
    .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        gap: 14px;
        margin: 18px 0;
    }
    .card {
        background: var(--panel);
        border: 1px solid var(--grid);
        border-radius: 12px;
        padding: 18px;
        margin-bottom: 16px;
        box-shadow: 0 3px 10px rgba(0,0,0,0.04);
    }
    .status.passed { color: var(--ok); font-weight: 700; }
    .status.warning { color: var(--warn); font-weight: 700; }
    .status.failed { color: var(--bad); font-weight: 700; }
    .error { color: var(--bad); }
    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
        margin: 8px 0;
    }
    th, td {
        border: 1px solid var(--grid);
        padding: 8px;
        text-align: left;
    }
    th { background: #eef5ed; }
    pre {
        background: #f7fbf7;
        border: 1px solid var(--grid);
        border-radius: 8px;
        padding: 10px;
        overflow-x: auto;
        font-size: 12px;
    }
    .kpi {
        font-size: 28px;
        font-weight: 700;
        color: var(--accent);
    }
    .label {
        color: var(--soft);
        text-transform: uppercase;
        font-size: 11px;
        letter-spacing: .1em;
    }
    .bar-wrap { margin: 6px 0; }
    .bar {
        height: 10px;
        border-radius: 999px;
        background: linear-gradient(90deg, #3aa86d, #0e6b5c);
    }
    """

    total_tests = len(report.tests)
    passed_tests = sum(1 for t in report.tests if t.status == "passed")
    warning_tests = sum(1 for t in report.tests if t.status == "warning")
    failed_tests = sum(1 for t in report.tests if t.status == "failed")

    return f"""
    <!DOCTYPE html>
    <html lang=\"en\">
    <head>
      <meta charset=\"UTF-8\" />
      <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
      <title>Disk Checker Report {report.run_id}</title>
      <style>{style}</style>
    </head>
    <body>
      <header>
                <h1 class="report-title">Disk Checker Report (Read-Only)</h1>
        <p>Run ID: <strong>{report.run_id}</strong></p>
        <p>Status: <strong>{report.status.upper()}</strong> | Started: {report.started_at} | Ended: {report.ended_at}</p>
      </header>
      <main>
        <section class=\"grid\">
          <div class=\"card\"><div class=\"label\">Tests Passed</div><div class=\"kpi\">{passed_tests}/{total_tests}</div></div>
          <div class=\"card\"><div class=\"label\">Tests Warning</div><div class=\"kpi\">{warning_tests}</div></div>
          <div class=\"card\"><div class=\"label\">Tests Failed</div><div class=\"kpi\">{failed_tests}</div></div>
          <div class=\"card\"><div class=\"label\">Filesystem</div><div class=\"kpi\" style=\"font-size:20px\">{report.system.mount.fs_type}</div></div>
        </section>

        <section class=\"card\">
          <h2>System Snapshot</h2>
          <p><strong>Host:</strong> {report.system.hostname}</p>
          <p><strong>Platform:</strong> {report.system.platform}</p>
          <p><strong>Python:</strong> {report.system.python}</p>
          <p><strong>CPU Count:</strong> {report.system.cpu_count}</p>
          <p><strong>Load Avg (1,5,15):</strong> {load_avg_text}</p>
          <p><strong>Mount Requested:</strong> {report.system.mount.requested_path}</p>
          <p><strong>Mount Resolved:</strong> {report.system.mount.resolved_path}</p>
          <p><strong>Detected Mountpoint:</strong> {report.system.mount.mountpoint} | <strong>Device:</strong> {report.system.mount.device}</p>
          <p><strong>Mount Options:</strong> {', '.join(report.system.mount.mount_options) if report.system.mount.mount_options else 'N/A'}</p>
          <p><strong>Total:</strong> {report.system.disk_total_bytes} bytes | <strong>Used:</strong> {report.system.disk_used_bytes} bytes | <strong>Free:</strong> {report.system.disk_free_bytes} bytes</p>
          <p><strong>Inodes:</strong> total {report.system.inode_total}, free {report.system.inode_free}</p>
          <div class=\"bar-wrap\">
            <div class=\"label\">Used Capacity</div>
            <div class=\"bar\" style=\"width:{(report.system.disk_used_bytes / max(1, report.system.disk_total_bytes)) * 100:.2f}%\"></div>
          </div>
        </section>

        <section class=\"card\">
          <h2>Run Warnings</h2>
          <ul>
            {''.join(f'<li>{w}</li>' for w in report.warnings) if report.warnings else '<li>None</li>'}
          </ul>
        </section>

        {''.join(tests_html)}

        <section class=\"card\">
          <h2>Config (Effective)</h2>
          <pre>{json.dumps(report.config, indent=2)}</pre>
        </section>
      </main>
    </body>
    </html>
    """


def render_aggregate_html(summary: AggregateRunSummary) -> str:
        rows = []
        for run in summary.runs:
                rows.append(
                        """
                        <tr>
                                <td>{device}</td>
                                <td>{mount}</td>
                                <td>{fs_type}</td>
                                <td><span class=\"status {status}\">{status_upper}</span></td>
                                <td>{warnings}</td>
                                <td>{tests_failed}</td>
                                <td>{json_report}</td>
                                <td>{html_report}</td>
                        </tr>
                        """.format(
                                device=run["device"],
                                mount=run["mount"],
                                fs_type=run["fs_type"],
                                status=run["status"],
                                status_upper=run["status"].upper(),
                                warnings=run["warning_count"],
                                tests_failed=run["failed_test_count"],
                                json_report=run["json_report"],
                                html_report=run["html_report"],
                        )
                )

        style = """
        :root {
                --bg: #f4f7f1;
                --panel: #ffffff;
                --ink: #122117;
                --soft: #5f6f61;
                --ok: #1f8a4c;
                --warn: #b36b00;
                --bad: #b02020;
                --grid: #d8e2d6;
        }
        body {
                font-family: "IBM Plex Sans", "DejaVu Sans", sans-serif;
                margin: 0;
                color: var(--ink);
                background: radial-gradient(circle at 10% 5%, #e7f3e9 0%, var(--bg) 55%);
        }
        header {
                padding: 28px;
                background: linear-gradient(120deg, #cbe6d3 0%, #d9f0e2 40%, #f3f9ef 100%);
                border-bottom: 1px solid #c3d9c7;
        }
        .report-title {
            font-family: "Payaya", "Papyrus", "Comic Sans MS", cursive;
            letter-spacing: 0.02em;
        }
        main { padding: 24px; max-width: 1200px; margin: 0 auto; }
        .card {
                background: var(--panel);
                border: 1px solid var(--grid);
                border-radius: 12px;
                padding: 18px;
                margin-bottom: 16px;
                box-shadow: 0 3px 10px rgba(0,0,0,0.04);
        }
        table {
                width: 100%;
                border-collapse: collapse;
                font-size: 13px;
                margin: 8px 0;
        }
        th, td {
                border: 1px solid var(--grid);
                padding: 8px;
                text-align: left;
        }
        th { background: #eef5ed; }
        .status.passed { color: var(--ok); font-weight: 700; }
        .status.warning { color: var(--warn); font-weight: 700; }
        .status.failed { color: var(--bad); font-weight: 700; }
        """

        return f"""
        <!DOCTYPE html>
        <html lang=\"en\">
        <head>
            <meta charset=\"UTF-8\" />
            <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
            <title>Disk Checker Aggregate Report {summary.run_id}</title>
            <style>{style}</style>
        </head>
        <body>
            <header>
                <h1 class="report-title">Disk Checker Aggregate Report (Read-Only)</h1>
                <p>Run ID: <strong>{summary.run_id}</strong></p>
                <p>Status: <strong>{summary.status.upper()}</strong> | Started: {summary.started_at} | Ended: {summary.ended_at}</p>
            </header>
            <main>
                <section class=\"card\">
                    <p><strong>Mount Input:</strong> {summary.mount_input}</p>
                    <p><strong>Mount Count:</strong> {summary.mount_count}</p>
                    <p><strong>Duration:</strong> {summary.duration_s:.2f}s</p>
                </section>
                <section class=\"card\">
                    <h2>Run Warnings</h2>
                    <ul>{''.join(f'<li>{w}</li>' for w in summary.warnings) if summary.warnings else '<li>None</li>'}</ul>
                </section>
                <section class=\"card\">
                    <h2>Per-Mount Results</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Device</th><th>Mount</th><th>FS</th><th>Status</th><th>Warnings</th><th>Failed Tests</th><th>JSON</th><th>HTML</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </section>
            </main>
        </body>
        </html>
        """


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only disk mount health checker and HTML report generator")
    parser.add_argument(
        "--mount",
        required=True,
        help="Mount directory, mounted device path, or 'all' to inspect all mounted disks",
    )
    parser.add_argument("--output-dir", default="./reports", help="Directory to place generated reports")
    parser.add_argument("--run-label", default="", help="Optional label appended to run ID")
    parser.add_argument("--allow-non-mount", action="store_true", help="Allow non-mount path for lab/testing")
    parser.add_argument("--sample-files", type=int, default=50, help="Number of existing files to sample-read")
    parser.add_argument("--sample-read-bytes", type=int, default=1048576, help="Bytes to read per sampled file")
    parser.add_argument("--max-walk-entries", type=int, default=50000, help="Traversal cap for very large filesystems")
    parser.add_argument("--usage-warn-percent", type=float, default=85.0, help="Warn threshold for disk usage percent")
    parser.add_argument("--usage-fail-percent", type=float, default=95.0, help="Fail threshold for disk usage percent")
    parser.add_argument("--inode-warn-percent", type=float, default=85.0, help="Warn threshold for inode usage percent")
    parser.add_argument("--inode-fail-percent", type=float, default=95.0, help="Fail threshold for inode usage percent")
    parser.add_argument("--verbose", action="store_true", help="Verbose logs")
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> AppConfig:
    mount = resolve_mount_argument(args.mount)
    output_dir = Path(args.output_dir).expanduser()

    policy = HealthPolicy(
        usage_warn_percent=args.usage_warn_percent,
        usage_fail_percent=args.usage_fail_percent,
        inode_warn_percent=args.inode_warn_percent,
        inode_fail_percent=args.inode_fail_percent,
    )

    if policy.usage_warn_percent >= policy.usage_fail_percent:
        raise DiskCheckError("usage-warn-percent must be lower than usage-fail-percent")
    if policy.inode_warn_percent >= policy.inode_fail_percent:
        raise DiskCheckError("inode-warn-percent must be lower than inode-fail-percent")

    run_label = args.run_label.strip() or "readonly"

    return AppConfig(
        mount_input=args.mount,
        mount=mount,
        output_dir=output_dir,
        run_label=run_label,
        allow_non_mount=args.allow_non_mount,
        sample_files=max(1, args.sample_files),
        sample_read_bytes=max(4096, args.sample_read_bytes),
        max_walk_entries=max(1000, args.max_walk_entries),
        policy=policy,
    )


def discover_all_mount_targets() -> List[Tuple[str, Path, str]]:
    """Discover mounted, directory-backed disk targets for --mount all."""
    targets: List[Tuple[str, Path, str]] = []
    seen_mounts: set[str] = set()

    with open("/proc/mounts", "r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 3:
                continue
            dev = decode_mount_field(parts[0])
            mountpoint = decode_mount_field(parts[1])
            fs_type = parts[2]

            # Only include real block devices to represent disks/partitions.
            if not dev.startswith("/dev/"):
                continue
            if dev.startswith("/dev/loop") or dev.startswith("/dev/ram") or dev.startswith("/dev/zram"):
                continue
            if fs_type in IGNORED_FS_TYPES:
                continue
            if mountpoint in seen_mounts:
                continue

            mp = Path(mountpoint)
            if not mp.exists() or not mp.is_dir():
                continue
            if not os.access(mp, os.R_OK | os.X_OK):
                continue

            seen_mounts.add(mountpoint)
            targets.append((dev, mp, fs_type))

    targets.sort(key=lambda item: str(item[1]))
    return targets


def build_config_for_mount(base_args: argparse.Namespace, mount_input: str, mount_path: Path) -> AppConfig:
    policy = HealthPolicy(
        usage_warn_percent=base_args.usage_warn_percent,
        usage_fail_percent=base_args.usage_fail_percent,
        inode_warn_percent=base_args.inode_warn_percent,
        inode_fail_percent=base_args.inode_fail_percent,
    )
    if policy.usage_warn_percent >= policy.usage_fail_percent:
        raise DiskCheckError("usage-warn-percent must be lower than usage-fail-percent")
    if policy.inode_warn_percent >= policy.inode_fail_percent:
        raise DiskCheckError("inode-warn-percent must be lower than inode-fail-percent")

    run_label = base_args.run_label.strip() or "readonly"

    return AppConfig(
        mount_input=mount_input,
        mount=mount_path,
        output_dir=Path(base_args.output_dir).expanduser(),
        run_label=run_label,
        allow_non_mount=base_args.allow_non_mount,
        sample_files=max(1, base_args.sample_files),
        sample_read_bytes=max(4096, base_args.sample_read_bytes),
        max_walk_entries=max(1000, base_args.max_walk_entries),
        policy=policy,
    )


def validate_config(config: AppConfig) -> MountDetails:
    if not config.mount.exists():
        raise DiskCheckError(f"Mount path does not exist: {config.mount}")
    if not config.mount.is_dir():
        raise DiskCheckError(f"Mount path is not a directory: {config.mount}")
    if not os.access(config.mount, os.R_OK | os.X_OK):
        raise DiskCheckError(f"Insufficient read permissions on mount path: {config.mount}")

    mount_info = find_mount_info(config.mount)
    if not mount_info.is_mountpoint and not config.allow_non_mount:
        raise DiskCheckError(
            "Provided --mount is not a mount point. "
            "Use --allow-non-mount to override for test environments."
        )

    return mount_info


def run_suite(config: AppConfig) -> RunReport:
    run_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{config.run_label}-{uuid.uuid4().hex[:8]}"
    start_ts = utc_now()
    start_perf = time.perf_counter()

    mount_info = validate_config(config)
    system = collect_system_snapshot(config, mount_info)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    context = ExecutionContext(config=config, interrupt=GracefulInterrupt())
    tests: List[DiskTest] = [MountHealthTest(), CapacityAndInodeTest(), DirectoryTraversalTest(), FileReadSampleTest()]

    results: List[TestResult] = []
    global_warnings: List[str] = [
        "This tool is read-only and performs filesystem-level checks only.",
        "Hardware-level SMART diagnostics are not included in this report.",
    ]

    for test in tests:
        if context.interrupt.requested:
            global_warnings.append("Interrupted before all tests completed")
            break

        LOGGER.info("Running test: %s", test.name)
        result = test.run(context)
        results.append(result)

    end_ts = utc_now()
    end_perf = time.perf_counter()

    status = "passed"
    if any(t.status == "failed" for t in results):
        status = "failed"
    elif any(t.status == "warning" for t in results):
        status = "warning"

    report = RunReport(
        run_id=run_id,
        started_at=start_ts,
        ended_at=end_ts,
        duration_s=end_perf - start_perf,
        status=status,
        config={
            "mount_input": config.mount_input,
            "mount": str(config.mount),
            "output_dir": str(config.output_dir),
            "run_label": config.run_label,
            "allow_non_mount": config.allow_non_mount,
            "sample_files": config.sample_files,
            "sample_read_bytes": config.sample_read_bytes,
            "max_walk_entries": config.max_walk_entries,
            "usage_warn_percent": config.policy.usage_warn_percent,
            "usage_fail_percent": config.policy.usage_fail_percent,
            "inode_warn_percent": config.policy.inode_warn_percent,
            "inode_fail_percent": config.policy.inode_fail_percent,
            "read_only_mode": True,
        },
        system=system,
        tests=results,
        warnings=global_warnings,
    )
    return report


def run_all_mount_suites(args: argparse.Namespace) -> Tuple[AggregateRunSummary, List[Tuple[RunReport, Path, Path]]]:
    started_at = utc_now()
    start_perf = time.perf_counter()
    aggregate_run_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-all-{uuid.uuid4().hex[:8]}"

    targets = discover_all_mount_targets()
    if not targets:
        raise DiskCheckError("No mounted disk targets found for --mount all")

    per_mount_reports: List[Tuple[RunReport, Path, Path]] = []
    run_rows: List[Dict[str, Any]] = []
    warnings: List[str] = [
        "This is an aggregate read-only run across all discovered mounted disks.",
        "Each row references a full per-mount HTML/JSON report generated in output-dir.",
    ]

    for dev, mountpoint, fs_type in targets:
        LOGGER.info("Running all-mount check for %s mounted on %s", dev, mountpoint)
        config = build_config_for_mount(args, dev, mountpoint)
        report = run_suite(config)
        json_path, html_path = write_reports(report, config.output_dir)
        per_mount_reports.append((report, json_path, html_path))

        run_rows.append(
            {
                "device": dev,
                "mount": str(mountpoint),
                "fs_type": fs_type,
                "status": report.status,
                "warning_count": len(report.warnings),
                "failed_test_count": sum(1 for t in report.tests if t.status == "failed"),
                "json_report": json_path.name,
                "html_report": html_path.name,
            }
        )

    ended_at = utc_now()
    end_perf = time.perf_counter()

    overall_status = "passed"
    if any(row["status"] == "failed" for row in run_rows):
        overall_status = "failed"
    elif any(row["status"] == "warning" for row in run_rows):
        overall_status = "warning"

    summary = AggregateRunSummary(
        run_id=aggregate_run_id,
        started_at=started_at,
        ended_at=ended_at,
        duration_s=end_perf - start_perf,
        status=overall_status,
        mount_input="all",
        mount_count=len(run_rows),
        config={
            "output_dir": str(Path(args.output_dir).expanduser()),
            "run_label": args.run_label.strip() or "readonly",
            "allow_non_mount": args.allow_non_mount,
            "sample_files": max(1, args.sample_files),
            "sample_read_bytes": max(4096, args.sample_read_bytes),
            "max_walk_entries": max(1000, args.max_walk_entries),
            "usage_warn_percent": args.usage_warn_percent,
            "usage_fail_percent": args.usage_fail_percent,
            "inode_warn_percent": args.inode_warn_percent,
            "inode_fail_percent": args.inode_fail_percent,
            "read_only_mode": True,
        },
        runs=run_rows,
        warnings=warnings,
    )
    return summary, per_mount_reports


def write_aggregate_reports(summary: AggregateRunSummary, output_dir: Path) -> Tuple[Path, Path]:
    json_path = output_dir / f"{summary.run_id}.json"
    html_path = output_dir / f"{summary.run_id}.html"

    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(asdict(summary), jf, indent=2)

    with open(html_path, "w", encoding="utf-8") as hf:
        hf.write(render_aggregate_html(summary))

    return json_path, html_path


def write_reports(report: RunReport, output_dir: Path) -> Tuple[Path, Path]:
    json_path = output_dir / f"{report.run_id}.json"
    html_path = output_dir / f"{report.run_id}.html"

    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(asdict(report), jf, indent=2)

    with open(html_path, "w", encoding="utf-8") as hf:
        hf.write(render_html(report))

    return json_path, html_path


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    try:
        if args.mount.strip().lower() == "all":
            output_dir = Path(args.output_dir).expanduser()
            output_dir.mkdir(parents=True, exist_ok=True)

            summary, per_mount_reports = run_all_mount_suites(args)
            agg_json_path, agg_html_path = write_aggregate_reports(summary, output_dir)

            LOGGER.info("Aggregate run complete with status: %s", summary.status)
            LOGGER.info("Aggregate JSON report: %s", agg_json_path)
            LOGGER.info("Aggregate HTML report: %s", agg_html_path)
            LOGGER.info("Per-mount reports generated: %d", len(per_mount_reports))

            if summary.status == "failed":
                return 2
            if summary.status == "warning":
                return 1
            return 0

        config = build_config(args)
        report = run_suite(config)
        json_path, html_path = write_reports(report, config.output_dir)

        LOGGER.info("Run complete with status: %s", report.status)
        LOGGER.info("JSON report: %s", json_path)
        LOGGER.info("HTML report: %s", html_path)

        if report.status == "failed":
            return 2
        if report.status == "warning":
            return 1
        return 0
    except DiskCheckError as exc:
        LOGGER.error("Validation error: %s", exc)
        return 3
    except KeyboardInterrupt:
        LOGGER.error("Interrupted")
        return 130
    except Exception as exc:  # pylint: disable=broad-except
        LOGGER.error("Fatal error: %s", exc)
        LOGGER.debug("Traceback:\n%s", traceback.format_exc())
        return 99


if __name__ == "__main__":
    raise SystemExit(main())
