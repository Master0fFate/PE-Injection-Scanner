import argparse
import ctypes
import json
import struct
import sys
import os
import hashlib
import ntpath
import zlib
from dataclasses import asdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path

FROZEN_EXE = getattr(sys, 'frozen', False)

_STD_OUTPUT_HANDLE = -11
if sys.platform == "win32":
    try:
        _kernel32 = ctypes.windll.kernel32
    except (AttributeError, OSError):
        _kernel32 = None
else:
    _kernel32 = None

if _kernel32:
    try:
        _console_handle = _kernel32.GetStdHandle(_STD_OUTPUT_HANDLE)
    except (OSError, AttributeError):
        _console_handle = None
else:
    _console_handle = None

_BLACK   = 0x0000
_BLUE    = 0x0001
_GREEN   = 0x0002
_CYAN    = 0x0003
_RED     = 0x0004
_MAGENTA = 0x0005
_YELLOW  = 0x0006
_WHITE   = 0x0007
_INTENSE = 0x0008

_BRIGHT_WHITE  = _WHITE | _INTENSE
_BRIGHT_RED    = _RED | _INTENSE
_BRIGHT_GREEN  = _GREEN | _INTENSE
_BRIGHT_YELLOW = _YELLOW | _INTENSE
_BRIGHT_CYAN   = _CYAN | _INTENSE
_DIM_WHITE     = _WHITE

_DEFAULT_COLOR = _WHITE
_DEFAULT_TERMINAL_WIDTH = 120
_MIN_TERMINAL_WIDTH = 80

class _CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_short * 2),
        ("dwCursorPosition", ctypes.c_short * 2),
        ("wAttributes", ctypes.c_ushort),
        ("srWindow", ctypes.c_short * 4),
        ("dwMaximumWindowSize", ctypes.c_short * 2),
    ]

if _kernel32 and _console_handle:
    _csbi = _CONSOLE_SCREEN_BUFFER_INFO()
    _kernel32.GetConsoleScreenBufferInfo(_console_handle, ctypes.byref(_csbi))
    _ORIGINAL_ATTRS = _csbi.wAttributes
else:
    _ORIGINAL_ATTRS = _DEFAULT_COLOR


def _set_color(color: int) -> None:
    if _kernel32 and _console_handle:
        _kernel32.SetConsoleTextAttribute(_console_handle, color)


def _reset_color() -> None:
    if _kernel32 and _console_handle:
        _kernel32.SetConsoleTextAttribute(_console_handle, _ORIGINAL_ATTRS)


def _get_terminal_width() -> int:
    if not (_kernel32 and _console_handle):
        return _DEFAULT_TERMINAL_WIDTH
    try:
        info = _CONSOLE_SCREEN_BUFFER_INFO()
        _kernel32.GetConsoleScreenBufferInfo(_console_handle, ctypes.byref(info))
        width = info.srWindow[2] - info.srWindow[0] + 1
        return max(width, _MIN_TERMINAL_WIDTH)
    except (OSError, AttributeError):
        return _DEFAULT_TERMINAL_WIDTH


def _console_safe(text: str) -> str:
    text = text.encode(sys.stdout.encoding or "utf-8", errors="backslashreplace").decode(sys.stdout.encoding or "utf-8")
    return "".join(char if (char in "\n\t" or ord(char) >= 32) and not 0xD800 <= ord(char) <= 0xDFFF and ord(char) != 127 else f"\\u{ord(char):04x}" for char in text)


def cprint(text: str, color: int = _DEFAULT_COLOR, end: str = "\n") -> None:
    _set_color(color)
    sys.stdout.write(_console_safe(text))
    sys.stdout.write(end)
    sys.stdout.flush()
    _reset_color()


def cprint_multi(segments: list[tuple[str, int]], end: str = "\n") -> None:
    for text, color in segments:
        _set_color(color)
        sys.stdout.write(_console_safe(text))
        sys.stdout.flush()
    _reset_color()
    sys.stdout.write(end)
    sys.stdout.flush()


def print_horizontal_line(width: int, char: str = "-", color: int = _DIM_WHITE) -> None:
    cprint(char * width, color)


def print_box(lines: list[str | tuple[str, int]], title: str = "",
              border_color: int = _BRIGHT_WHITE, width: int = 0) -> None:
    if width <= 0:
        width = _get_terminal_width() - 2
    inner = width - 2

    if title:
        pad = inner - len(title) - 2
        left_pad = pad // 2
        right_pad = pad - left_pad
        cprint_multi([
            ("\u250c", border_color),
            ("\u2500" * left_pad + " ", border_color),
            (title, _BRIGHT_WHITE),
            (" " + "\u2500" * right_pad, border_color),
            ("\u2510", border_color),
        ])
    else:
        cprint("\u250c" + "\u2500" * inner + "\u2510", border_color)

    for line in lines:
        if isinstance(line, tuple):
            text, color = line
        else:
            text = line
            color = _DEFAULT_COLOR

        visible_len = len(text)
        padding = inner - visible_len
        if padding < 0:
            text = text[:inner]
            padding = 0

        cprint_multi([
            ("\u2502", border_color),
            (text + " " * padding, color),
            ("\u2502", border_color),
        ])

    cprint("\u2514" + "\u2500" * inner + "\u2518", border_color)


def print_table(headers: list[tuple[str, int]], rows: list[list[tuple[str, int]]],
                col_widths: list[int], title: str = "",
                header_color: int = _BRIGHT_WHITE,
                border_color: int = _DIM_WHITE,
                show_lines: bool = True) -> None:
    total_width = sum(col_widths) + len(col_widths) + 1

    if title:
        pad = (total_width - len(title)) // 2
        cprint(" " * max(pad, 0) + title, _BRIGHT_WHITE)
        print()

    top = "\u250c"
    for i, w in enumerate(col_widths):
        top += "\u2500" * (w + 2)
        top += "\u252c" if i < len(col_widths) - 1 else "\u2510"
    cprint(top, border_color)

    segments = [("\u2502", border_color)]
    for i, (hdr_text, _) in enumerate(headers):
        cell = f" {hdr_text:<{col_widths[i]}} "
        segments.append((cell, header_color))
        segments.append(("\u2502", border_color))
    cprint_multi(segments)

    sep = "\u251c"
    for i, w in enumerate(col_widths):
        sep += "\u2500" * (w + 2)
        sep += "\u253c" if i < len(col_widths) - 1 else "\u2524"
    cprint(sep, border_color)

    for row_idx, row in enumerate(rows):
        segments = [("\u2502", border_color)]
        for i, (cell_text, cell_color) in enumerate(row):
            w = col_widths[i]
            truncated = cell_text[:w]
            cell = f" {truncated:<{w}} "
            segments.append((cell, cell_color))
            segments.append(("\u2502", border_color))
        cprint_multi(segments)

        if show_lines and row_idx < len(rows) - 1:
            row_sep = "\u251c"
            for i, w in enumerate(col_widths):
                row_sep += "\u2500" * (w + 2)
                row_sep += "\u253c" if i < len(col_widths) - 1 else "\u2524"
            cprint(row_sep, border_color)

    bottom = "\u2514"
    for i, w in enumerate(col_widths):
        bottom += "\u2500" * (w + 2)
        bottom += "\u2534" if i < len(col_widths) - 1 else "\u2518"
    cprint(bottom, border_color)


def print_progress(description: str, current: int, total: int, bar_width: int = 40) -> None:
    if total == 0:
        pct = 100.0
    else:
        pct = (current / total) * 100.0
    filled = int(bar_width * current / max(total, 1))
    bar = "\u2588" * filled + "\u2591" * (bar_width - filled)
    line = f"\r  {description} [{bar}] {pct:5.1f}% ({current}/{total})"
    _set_color(_BRIGHT_CYAN)
    sys.stdout.write(line)
    sys.stdout.flush()
    _reset_color()
    if current >= total:
        sys.stdout.write("\r" + " " * (len(line) + 5) + "\r")
        sys.stdout.flush()


PREFETCH_DIR = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "Prefetch"
SCCA_SIGNATURE = b"SCCA"
MAM_SIGNATURES = [b"MAM\x04", b"MAM\x84"]
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

EXPECTED_PATHS = {
    "RUNTIMEBROKER.EXE": ["\\WINDOWS\\SYSTEM32\\RUNTIMEBROKER.EXE"],
    "CTFMON.EXE": ["\\WINDOWS\\SYSTEM32\\CTFMON.EXE"],
    "SVCHOST.EXE": ["\\WINDOWS\\SYSTEM32\\SVCHOST.EXE"],
    "NOTEPAD.EXE": [
        "\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE",
        "\\WINDOWS\\NOTEPAD.EXE",
    ],
    "DLLHOST.EXE": ["\\WINDOWS\\SYSTEM32\\DLLHOST.EXE"],
    "CONHOST.EXE": ["\\WINDOWS\\SYSTEM32\\CONHOST.EXE"],
    "TASKHOSTW.EXE": ["\\WINDOWS\\SYSTEM32\\TASKHOSTW.EXE"],
    "SPOTIFY.EXE": [
        "\\PROGRAM FILES\\SPOTIFY\\SPOTIFY.EXE",
        "\\USERS\\%LOCALAPPDATA%\\SPOTIFY\\SPOTIFY.EXE",
    ],
    "SEARCHPROTOCOLHOST.EXE": ["\\WINDOWS\\SYSTEM32\\SEARCHPROTOCOLHOST.EXE"],
    "WERFAULT.EXE": ["\\WINDOWS\\SYSTEM32\\WERFAULT.EXE"],
}


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "NO_ANOMALY"


SEVERITY_COLORS = {
    Severity.CRITICAL: _BRIGHT_RED,
    Severity.HIGH: _RED | _INTENSE,
    Severity.MEDIUM: _BRIGHT_YELLOW,
    Severity.LOW: _BRIGHT_CYAN,
    Severity.CLEAN: _BRIGHT_GREEN,
}


@dataclass
class PrefetchEntry:
    filename: str
    executable_name: str
    prefetch_hash: int
    version: int
    file_size: int
    process_path: str
    file_references: list[str]
    run_count: int
    last_run: datetime | None
    created: datetime | None
    modified: datetime | None
    source_path: str
    source_sha256: str = ""
    last_runs: list[datetime] = field(default_factory=list)
    last_run_filetimes: list[int] = field(default_factory=list)
    path_candidates: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class Finding:
    entry: PrefetchEntry
    severity: Severity
    reasons: list[str] = field(default_factory=list)
    confidence: str = "low"
    evidence_type: str = "prefetch_heuristic"


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, OSError):
        return False


def filetime_to_datetime(ft: int) -> datetime | None:
    if ft == 0 or ft < 0:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


XPRESS_HUFFMAN = 4
MAX_PREFETCH_SIZE = 50 * 1024 * 1024
MAX_DECOMPRESSED_SIZE = 64 * 1024 * 1024
MAX_METRICS = 50_000
MAX_REFERENCE_CHARS = 32_768
MAX_REFERENCE_BYTES = 16 * 1024 * 1024
LIMITATION = "Prefetch anomalies are triage clues, not proof of injection or hollowing; absence of findings does not establish a clean host."


class PrefetchError(ValueError):
    """Unsupported, incomplete, or malformed evidence."""


def decompress_mam(data: bytes) -> bytes:
    if len(data) < 8 or data[:4] not in MAM_SIGNATURES:
        raise PrefetchError("Unsupported MAM variant (expected MAM04 or MAM84)")
    payload_offset = 8
    if data[3] == 0x84:
        if len(data) < 12:
            raise PrefetchError("Truncated MAM checksum header")
        expected_crc = struct.unpack_from("<I", data, 8)[0]
        actual_crc = zlib.crc32(data[:8] + bytes(4) + data[12:]) & 0xffffffff
        if expected_crc != actual_crc:
            raise PrefetchError("MAM checksum mismatch")
        payload_offset = 12
    size = struct.unpack_from("<I", data, 4)[0]
    if not 0 < size <= MAX_DECOMPRESSED_SIZE:
        raise PrefetchError("Invalid or oversized decompression length")
    if sys.platform != "win32":
        raise PrefetchError("MAM decompression requires Windows; use an uncompressed evidence copy")
    ntdll = ctypes.WinDLL("ntdll")
    workspace_size, fragment_size = ctypes.c_ulong(), ctypes.c_ulong()
    get_size = ntdll.RtlGetCompressionWorkSpaceSize
    get_size.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    get_size.restype = ctypes.c_long
    if get_size(XPRESS_HUFFMAN, ctypes.byref(workspace_size), ctypes.byref(fragment_size)) != 0:
        raise PrefetchError("Could not query decompression workspace")
    if not 0 < fragment_size.value <= MAX_DECOMPRESSED_SIZE:
        raise PrefetchError("Invalid decompression workspace size")
    workspace = ctypes.create_string_buffer(fragment_size.value)
    output = ctypes.create_string_buffer(size)
    compressed = ctypes.create_string_buffer(data[payload_offset:])
    final_size = ctypes.c_ulong()
    decompress = ntdll.RtlDecompressBufferEx
    decompress.argtypes = [ctypes.c_ushort, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
                           ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    decompress.restype = ctypes.c_long
    status = decompress(XPRESS_HUFFMAN, output, size, compressed, len(data) - payload_offset,
                        ctypes.byref(final_size), workspace)
    if status != 0 or final_size.value != size:
        raise PrefetchError("MAM decompression failed or output length mismatched")
    return output.raw[:size]


def _span(data: bytes, offset: int, length: int, label: str) -> bytes:
    if offset < 0 or length < 0 or offset > len(data) or length > len(data) - offset:
        raise PrefetchError(f"{label} extends beyond file")
    return data[offset:offset + length]


def _utf16(data: bytes, label: str) -> str:
    try:
        return data.decode("utf-16-le", errors="surrogatepass")
    except UnicodeError as exc:
        raise PrefetchError(f"Invalid UTF-16 in {label}") from exc


def parse_prefetch_file(filepath: Path) -> PrefetchEntry:
    # Bounded read, including files that change after stat; never load an unbounded file.
    with filepath.open("rb") as stream:
        raw = stream.read(MAX_PREFETCH_SIZE + 1)
    if len(raw) > MAX_PREFETCH_SIZE:
        raise PrefetchError("Input exceeds size limit")
    data = decompress_mam(raw) if raw.startswith(b"MAM") else raw
    _span(data, 0, 84, "header")
    version, signature = struct.unpack_from("<I4s", data)
    if signature != SCCA_SIGNATURE:
        raise PrefetchError("Invalid SCCA signature")
    # Layout sources and support boundaries are documented in docs/evidence-model.md.
    layouts = {17: (152, 20, 8, 120, 1, 144),
               23: (240, 32, 12, 128, 1, 152),
               26: (304, 32, 12, 128, 8, 208),
               30: (304, 32, 12, 128, 8, 208),
               31: (296, 32, 12, 128, 8, 200)}
    if version not in layouts:
        raise PrefetchError(f"Unsupported Prefetch version {version}")
    if version in (30, 31):
        _span(data, 84, 4, "metrics offset")
        metric_start = struct.unpack_from("<I", data, 84)[0]
        if metric_start == 296:
            layouts[version] = (296, 32, 12, 128, 8, 200)
        elif version == 31 or metric_start != 304:
            raise PrefetchError("Unsupported v30/v31 file information layout")
    minimum, metric_size, name_field, time_offset, time_count, count_offset = layouts[version]
    _span(data, 0, minimum, "file information")
    declared_size = struct.unpack_from("<I", data, 12)[0]
    if declared_size != len(data):
        raise PrefetchError("Declared file size does not match decompressed length")
    executable = _utf16(data[16:76], "executable name").split("\x00", 1)[0]
    if not executable or ntpath.basename(executable) != executable:
        raise PrefetchError("Missing or invalid executable name")
    metrics_offset, metrics_count = struct.unpack_from("<II", data, 84)
    strings_offset, strings_size = struct.unpack_from("<II", data, 100)
    if metrics_offset < minimum or strings_offset < minimum:
        raise PrefetchError("Section overlaps header or file information")
    if metrics_count > MAX_METRICS:
        raise PrefetchError("Metric count exceeds analysis budget")
    _span(data, metrics_offset, metrics_count * metric_size, "metrics section")
    strings = _span(data, strings_offset, strings_size, "filename strings section")
    if strings_offset < metrics_offset + metrics_count * metric_size:
        raise PrefetchError("Filename strings overlap metrics")
    if strings_size % 2:
        raise PrefetchError("Odd filename strings length")
    refs, seen_refs = [], set()
    decoded_bytes = 0
    for i in range(metrics_count):
        offset, chars = struct.unpack_from("<II", data, metrics_offset + i * metric_size + name_field)
        decoded_bytes += chars * 2
        if chars > MAX_REFERENCE_CHARS or decoded_bytes > MAX_REFERENCE_BYTES:
            raise PrefetchError("Filename references exceed analysis budget")
        if offset % 2:
            raise PrefetchError("Misaligned filename offset")
        value = _utf16(_span(strings, offset, chars * 2, "metric filename"), "metric filename").rstrip("\x00")
        if "\x00" in value:
            raise PrefetchError("Embedded null in metric filename")
        if value and value not in seen_refs:
            seen_refs.add(value)
            refs.append(value)
    candidates = list(dict.fromkeys(ref for ref in refs if ntpath.basename(ref).casefold() == executable.casefold()))
    raw_times = [struct.unpack_from("<Q", data, time_offset + i * 8)[0] for i in range(time_count)]
    timestamps = [filetime_to_datetime(value) for value in raw_times]
    warnings = []
    if any(value and timestamp is None for value, timestamp in zip(raw_times, timestamps)):
        warnings.append("Unrepresentable FILETIME retained in last_run_filetimes")
    if len(candidates) > 1:
        warnings.append("Multiple matching executable references; process image path is ambiguous")
    if len(executable) == 29:
        warnings.append("Header executable name may be truncated")
    stat = filepath.stat()
    # POSIX ctime is metadata change time, not creation time.
    birth = getattr(stat, "st_birthtime", stat.st_ctime if sys.platform == "win32" else None)
    return PrefetchEntry(
        filename=filepath.name, executable_name=executable,
        prefetch_hash=struct.unpack_from("<I", data, 76)[0], version=version,
        file_size=len(data), process_path=candidates[0] if len(candidates) == 1 else "",
        file_references=refs, run_count=struct.unpack_from("<I", data, count_offset)[0],
        last_run=timestamps[0], created=datetime.fromtimestamp(birth, timezone.utc) if birth is not None else None,
        modified=datetime.fromtimestamp(stat.st_mtime, timezone.utc), source_path=str(filepath),
        source_sha256=hashlib.sha256(raw).hexdigest(), last_runs=[t for t in timestamps if t],
        path_candidates=candidates, warnings=warnings, last_run_filetimes=raw_times)


def evaluate_entry(entry: PrefetchEntry) -> Finding:
    reasons = list(entry.warnings)
    severity = Severity.LOW if reasons else Severity.CLEAN
    if not entry.process_path:
        severity = Severity.LOW
        reasons.append("No unique matching executable reference; incomplete traces and truncated names can explain this")
    else:
        name, path = entry.executable_name.upper(), entry.process_path.replace("/", "\\").upper()
        # Installation-dependent applications intentionally have no fixed path rule.
        expected = EXPECTED_PATHS.get(name, []) if name not in {"NOTEPAD.EXE", "SPOTIFY.EXE"} else []
        expected = expected + [p.replace("\\SYSTEM32\\", "\\SYSWOW64\\") for p in expected]
        if expected and not any(path.endswith(p) for p in expected):
            severity = Severity.MEDIUM
            reasons.append("Executable reference differs from common Windows locations; check custom Windows roots, servicing and legitimate copies")
    return Finding(entry, severity, reasons)


def scan_prefetch_directory(prefetch_path: Path, issues: list[dict] | None = None) -> tuple[list[PrefetchEntry], list[Finding]]:
    issues = issues if issues is not None else []
    pf_files = sorted(p for p in prefetch_path.iterdir() if p.suffix.lower() == ".pf" and p.is_file())
    entries, findings = [], []
    for idx, path in enumerate(pf_files, 1):
        try:
            entry = parse_prefetch_file(path)
        except (OSError, ValueError, struct.error) as exc:
            issues.append({"source_path": str(path), "error": str(exc), "status": "not_analyzed"})
        else:
            entries.append(entry)
            finding = evaluate_entry(entry)
            if finding.severity != Severity.CLEAN:
                findings.append(finding)
        if sys.stdout.isatty():
            print_progress("Parsing prefetch files", idx, len(pf_files))
    return entries, findings


def render_findings(findings: list[Finding]) -> None:
    if not findings:
        print_box(
            [("  No Prefetch heuristics flagged. This does not rule out compromise.", _BRIGHT_GREEN)],
            title="Results",
            border_color=_BRIGHT_GREEN,
        )
        return

    findings.sort(key=lambda f: list(Severity).index(f.severity))

    col_widths = [10, 26, 44, 5, 50]
    headers = [
        ("Severity", 0),
        ("Executable", 0),
        ("Process Path", 0),
        ("Runs", 0),
        ("Reason", 0),
    ]

    rows = []
    for f in findings:
        color = SEVERITY_COLORS[f.severity]
        path_display = f.entry.process_path if f.entry.process_path else "<EMPTY>"
        reason_text = "; ".join(f.reasons)

        rows.append([
            (f.severity.value, color),
            (f.entry.executable_name, color),
            (path_display, _BRIGHT_RED if not f.entry.process_path else _DEFAULT_COLOR),
            (str(f.entry.run_count), _DEFAULT_COLOR),
            (reason_text, _DEFAULT_COLOR),
        ])

    print_table(
        headers=headers,
        rows=rows,
        col_widths=col_widths,
        title="Detection Results",
        show_lines=True,
    )


def render_summary(entries: list[PrefetchEntry], findings: list[Finding]) -> None:
    counts: dict[Severity, int] = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    counts[Severity.CLEAN] = len(entries) - len(findings)

    lines: list[str | tuple[str, int]] = [
        (f"  Total prefetch entries parsed:  {len(entries)}", _BRIGHT_WHITE),
        ("", _DEFAULT_COLOR),
    ]

    for sev in Severity:
        color = SEVERITY_COLORS[sev]
        lines.append((f"  {sev.value:>10}  {counts[sev]}", color))

    critical_or_high = counts[Severity.CRITICAL] + counts[Severity.HIGH]
    lines.append(("", _DEFAULT_COLOR))

    if critical_or_high > 0:
        lines.append(
            (f"  !  {critical_or_high} priority finding(s) require corroboration.", _BRIGHT_RED)
        )
    elif counts[Severity.MEDIUM] > 0:
        lines.append(
            ("  !  Possible indicators found. Manual review recommended.", _BRIGHT_YELLOW)
        )
    else:
        lines.append(("  +  No higher-priority Prefetch clues. Coverage is limited.", _BRIGHT_GREEN))

    print_box(lines, title="Scan Summary", border_color=_BRIGHT_WHITE)


def render_all_entries(entries: list[PrefetchEntry], flagged_files: set[str]) -> None:
    col_widths = [28, 56, 5, 9]
    headers = [
        ("Executable", 0),
        ("Process Path", 0),
        ("Runs", 0),
        ("Status", 0),
    ]

    rows = []
    for entry in sorted(entries, key=lambda e: e.executable_name):
        is_flagged = entry.filename in flagged_files
        color = _BRIGHT_RED if is_flagged else _DEFAULT_COLOR
        status_text = "FLAGGED" if is_flagged else "NO FLAG"
        status_color = _BRIGHT_RED if is_flagged else _BRIGHT_GREEN
        path_display = entry.process_path if entry.process_path else "<none>"

        rows.append([
            (entry.executable_name, color),
            (path_display, _DIM_WHITE if not entry.process_path else _DEFAULT_COLOR),
            (str(entry.run_count), _DEFAULT_COLOR),
            (status_text, status_color),
        ])

    print_table(
        headers=headers,
        rows=rows,
        col_widths=col_widths,
        title="All Prefetch Entries",
        show_lines=False,
    )


def export_results(entries: list[PrefetchEntry], findings: list[Finding], output_path: str,
                   issues: list[dict] | None = None, sysmon: dict | None = None) -> None:
    report = {
        "schema_version": 2, "scan_time": datetime.now(timezone.utc).isoformat(),
        "limitations": [LIMITATION, "Filesystem timestamps describe the evidence copy, not necessarily the original host."],
        "total_entries": len(entries), "total_findings": len(findings),
        "coverage": {"scope": "prefetch", "parsed": len(entries), "not_analyzed": len(issues or []),
                     "status": "partial" if issues else ("complete_for_supplied_files" if entries else "no_prefetch_evidence")},
        "parse_issues": issues or [],
        "entries": [asdict(entry) for entry in entries],
        "findings": [{"severity": f.severity.value, "confidence": f.confidence,
                      "evidence_type": f.evidence_type, "prefetch_file": f.entry.filename,
                      "source_path": f.entry.source_path, "source_sha256": f.entry.source_sha256,
                      "reasons": f.reasons} for f in findings],
        "sysmon": sysmon,
    }
    def serialize(value):
        if isinstance(value, datetime):
            return value.isoformat()
        raise TypeError(type(value).__name__)
    # Exclusive creation prevents accidental overwrite of evidence or an existing report.
    with open(output_path, "x", encoding="utf-8") as fp:
        json.dump(report, fp, indent=2, ensure_ascii=True, default=serialize)
    cprint(f"  Report saved to: {output_path}", _BRIGHT_GREEN)


def display_banner() -> None:
    lines: list[str | tuple[str, int]] = [
        ("", _DEFAULT_COLOR),
        ("    PE Evidence Triage", _BRIGHT_WHITE),
        ("    Read-only Prefetch and Sysmon evidence triage", _DIM_WHITE),
        ("", _DEFAULT_COLOR),
    ]
    print_box(lines, border_color=_BRIGHT_RED)
    print()


def _pause() -> None:
    # For frozen EXE, use os.system("pause")
    if FROZEN_EXE:
        os.system("pause >nul")
        return
    
    # For Python scripts, always try to pause
    # Try msvcrt first (Windows)
    try:
        import msvcrt
        cprint("  Press any key to continue...", _DIM_WHITE)
        msvcrt.getch()
        return
    except (ImportError, AttributeError):
        pass
    
    # Try input() as fallback for cross-platform
    try:
        input("  Press Enter to continue...")
    except (EOFError, KeyboardInterrupt):
        pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Triage Prefetch anomalies and exported Sysmon evidence (not proof of compromise)"
    )
    parser.add_argument(
        "--prefetch-dir",
        type=str,
        default=None,
        help="Path to Prefetch evidence (defaults to local Windows Prefetch unless --sysmon-xml is used)",
    )
    parser.add_argument(  # type: ignore[func-returns-value]
        "--all",
        action="store_true",
        help="Display all prefetch entries",
    )
    parser.add_argument(  # type: ignore[func-returns-value]
        "--export",
        type=str,
        default="",
        help="Export results to a JSON file",
    )
    parser.add_argument(  # type: ignore[func-returns-value]
        "--no-banner",
        action="store_true",
        help="Suppress the startup banner",
    )
    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="Disable the pause at the end of execution",
    )
    parser.add_argument("--sysmon-xml", help="Read an existing Sysmon XML export; never installs or configures Sysmon")
    args = parser.parse_args()

    if not args.no_banner:
        display_banner()

    if sys.platform == "win32" and not is_admin():
        cprint(
            "  !  Not running as administrator. Some prefetch files may be inaccessible.\n",
            _BRIGHT_YELLOW,
        )

    prefetch_path = Path(args.prefetch_dir) if args.prefetch_dir else PREFETCH_DIR
    scan_prefetch = args.prefetch_dir is not None or not args.sysmon_xml
    issues = []
    entries, findings = [], []
    try:
        if scan_prefetch and prefetch_path.is_dir():
            entries, findings = scan_prefetch_directory(prefetch_path, issues)
        elif scan_prefetch:
            raise OSError(f"Prefetch directory not found: {prefetch_path}")
        sysmon = None
        if args.sysmon_xml:
            from sysmon_evidence import analyze_sysmon_xml
            sysmon = analyze_sysmon_xml(Path(args.sysmon_xml))
        render_findings(findings)
        render_summary(entries, findings)
        cprint(LIMITATION, _BRIGHT_YELLOW)
        for issue in issues:
            cprint(f"Not analyzed: {issue['source_path']}: {issue['error']}", _BRIGHT_YELLOW)
        if sysmon is not None:
            cprint(f"Sysmon: {len(sysmon['findings'])} evidence finding(s), {len(sysmon['issues'])} issue(s)")
            for finding in sysmon["findings"]:
                cprint(f"  {finding['severity']} event {finding['event_id']}, record {finding['record_id']}: {finding['reason']}")
        if args.all:
            render_all_entries(entries, {f.entry.filename for f in findings})
        if args.export:
            export_results(entries, findings, args.export, issues, sysmon)
    except (OSError, ValueError) as exc:
        cprint(f"Scan failed: {exc}", _BRIGHT_RED)
        sys.exit(1)
    if issues or (sysmon and sysmon["issues"]):
        sys.exit(2)
    if not entries and not sysmon:
        cprint("No supported evidence was analyzed.", _BRIGHT_YELLOW)
        sys.exit(2)

    print()
    if not args.no_pause and sys.stdin.isatty():
        _pause()


if __name__ == "__main__":
    main()
