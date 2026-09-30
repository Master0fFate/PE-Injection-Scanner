"""Synthetic Prefetch fixtures with independently specified binary offsets.

No test reads live Prefetch, launches a fixture, or changes system configuration.
Native compression tests run only on Windows and compress inert bytes in memory.
"""

import contextlib
import ctypes
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zlib

import pe_injection_scan as scanner


# Literal layouts come from libscca's file-format specification, not the parser.
# (version, metrics offset, entry size, filename field, first time, time slots,
#  run-count offset). The two version-30 layouts deliberately differ.
LAYOUTS = (
    (17, 0x98, 20, 8, 0x78, 1, 0x90),
    (23, 0xF0, 32, 12, 0x80, 1, 0x98),
    (26, 0x130, 32, 12, 0x80, 8, 0xD0),
    (30, 0x130, 32, 12, 0x80, 8, 0xD0),
    (30, 0x128, 32, 12, 0x80, 8, 0xC8),
    (31, 0x128, 32, 12, 0x80, 8, 0xC8),
)
JAN_2025 = 133801632000000000
NORMAL_IMAGE = r"\DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\SVCHOST.EXE"


def fixture(layout=LAYOUTS[2], *, executable="SVCHOST.EXE", refs=None,
            times=None, run_count=19):
    """Return raw SCCA bytes; offsets and lengths are deliberately independent."""
    version, start, width, name_field, time_offset, slots, count_offset = layout
    if refs is None:
        # The executable is second to catch byte-offset/code-unit confusion.
        refs = [r"\DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\KERNEL32.DLL", NORMAL_IMAGE]
    if times is None:
        times = [JAN_2025 + 7] + [JAN_2025 - i * 10000000 for i in range(1, slots)]
    strings = bytearray()
    metrics = bytearray(len(refs) * width)
    for index, ref in enumerate(refs):
        encoded = ref.encode("utf-16-le", errors="surrogatepass")
        struct.pack_into("<II", metrics, index * width + name_field,
                         len(strings), len(encoded) // 2)
        strings.extend(encoded + b"\x00\x00")
    data = bytearray(start) + metrics + strings
    struct.pack_into("<I4sII", data, 0, version, b"SCCA", 17, len(data))
    encoded_name = executable.encode("utf-16-le", errors="surrogatepass")
    if len(encoded_name) > 58:
        raise ValueError("Fixture name exceeds 29 UTF-16 code units")
    data[16:16 + len(encoded_name)] = encoded_name
    struct.pack_into("<I", data, 76, 0xA1B2C3D4)
    string_start = start + len(metrics)
    struct.pack_into("<IIIIIIIII", data, 84,
                     start, len(refs), string_start, 0,
                     string_start, len(strings), len(data), 0, 0)
    for index, value in enumerate(times[:slots]):
        struct.pack_into("<Q", data, time_offset + 8 * index, value)
    struct.pack_into("<I", data, count_offset, run_count)
    return bytes(data)


def changed_u32(data, offset, value):
    data = bytearray(data)
    struct.pack_into("<I", data, offset, value)
    return bytes(data)


def mam(payload, uncompressed_size, *, crc=False):
    header = b"MAM" + (b"\x84" if crc else b"\x04") + struct.pack("<I", uncompressed_size)
    if not crc:
        return header + payload
    checksum = zlib.crc32(header + bytes(4) + payload) & 0xffffffff
    return header + struct.pack("<I", checksum) + payload


class PrefetchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def write(self, data, filename="SVCHOST.EXE-A1B2C3D4.pf"):
        path = self.directory / filename
        path.write_bytes(data)
        return path

    def parse(self, data, filename="SVCHOST.EXE-A1B2C3D4.pf"):
        return scanner.parse_prefetch_file(self.write(data, filename))

    def test_all_six_layouts(self):
        for layout in LAYOUTS:
            with self.subTest(version=layout[0], metrics_offset=hex(layout[1])):
                raw = fixture(layout)
                entry = self.parse(raw)
                self.assertEqual(entry.version, layout[0])
                self.assertEqual(entry.run_count, 19)
                self.assertEqual(entry.executable_name, "SVCHOST.EXE")
                self.assertEqual(entry.process_path, NORMAL_IMAGE)
                self.assertEqual(len(entry.file_references), 2)
                self.assertEqual(entry.prefetch_hash, 0xA1B2C3D4)
                self.assertEqual(entry.file_size, len(raw))
                self.assertEqual(entry.source_sha256, hashlib.sha256(raw).hexdigest())
                self.assertEqual(entry.last_run.isoformat(), "2025-01-01T00:00:00+00:00")
                self.assertEqual(len(entry.last_runs), layout[5])
                self.assertEqual(entry.last_run_filetimes[0], JAN_2025 + 7)

    def test_raw_filetimes_preserve_zero_unrepresentable_and_submicrosecond(self):
        values = [JAN_2025 + 9, 0, 0xffffffffffffffff, JAN_2025 - 10, 0, 0, 0, 0]
        entry = self.parse(fixture(times=values))
        self.assertEqual(entry.last_run_filetimes, values)
        self.assertEqual(len(entry.last_runs), 2)

    def test_zero_first_time_does_not_promote_older_time_to_last_run(self):
        entry = self.parse(fixture(times=[0, JAN_2025]))
        self.assertIsNone(entry.last_run)
        self.assertEqual(len(entry.last_runs), 1)

    def test_executable_matching_is_exact_basename_not_suffix(self):
        refs = [r"C:\Temp\NOTSVCHOST.EXE", r"C:\Temp\SVCHOST.EXE.old",
                r"C:\Temp\SVCHOST.EXE\file.txt"]
        entry = self.parse(fixture(refs=refs))
        self.assertEqual(entry.path_candidates, [])
        self.assertEqual(entry.process_path, "")

    def test_exact_basename_matching_is_case_insensitive(self):
        image = r"C:\Windows\System32\svchost.exe"
        entry = self.parse(fixture(refs=[image]))
        self.assertEqual(entry.path_candidates, [image])
        self.assertEqual(entry.process_path, image)

    def test_duplicate_references_do_not_create_ambiguity(self):
        entry = self.parse(fixture(refs=[NORMAL_IMAGE, NORMAL_IMAGE]))
        self.assertEqual(entry.file_references, [NORMAL_IMAGE])
        self.assertEqual(entry.path_candidates, [NORMAL_IMAGE])

    def test_multiple_matching_paths_are_ambiguous_not_arbitrarily_selected(self):
        refs = [NORMAL_IMAGE, r"C:\Temp\SVCHOST.EXE"]
        entry = self.parse(fixture(refs=refs))
        self.assertEqual(entry.path_candidates, refs)
        self.assertEqual(entry.process_path, "")
        self.assertTrue(any("ambiguous" in item.lower() for item in entry.warnings))
        finding = scanner.evaluate_entry(entry)
        self.assertEqual(finding.severity, scanner.Severity.LOW)
        self.assertEqual(finding.confidence, "low")

    def test_missing_references_are_low_confidence(self):
        entry = self.parse(fixture(refs=[]))
        finding = scanner.evaluate_entry(entry)
        self.assertEqual(finding.severity, scanner.Severity.LOW)
        self.assertEqual(finding.confidence, "low")
        self.assertEqual(finding.evidence_type, "prefetch_heuristic")

    def test_syswow64_is_accepted(self):
        entry = self.parse(fixture(refs=[r"C:\Windows\SysWOW64\svchost.exe"]))
        self.assertEqual(scanner.evaluate_entry(entry).severity, scanner.Severity.CLEAN)

    def test_install_variable_applications_have_no_fixed_path_rule(self):
        for executable, path in (
            ("SPOTIFY.EXE", r"C:\Users\Analyst\AppData\Roaming\Spotify\Spotify.exe"),
            ("NOTEPAD.EXE", r"C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_1\Notepad\Notepad.exe"),
        ):
            with self.subTest(executable=executable):
                entry = self.parse(fixture(executable=executable, refs=[path]))
                self.assertEqual(scanner.evaluate_entry(entry).severity, scanner.Severity.CLEAN)

    def test_unusual_system_path_is_not_high_confidence_injection(self):
        entry = self.parse(fixture(refs=[r"C:\Tools\SVCHOST.EXE"]))
        finding = scanner.evaluate_entry(entry)
        self.assertEqual(finding.severity, scanner.Severity.MEDIUM)
        self.assertEqual(finding.confidence, "low")

    def test_truncated_header_name_has_warning(self):
        entry = self.parse(fixture(executable="A" * 29, refs=[]))
        self.assertTrue(any("truncated" in warning.lower() for warning in entry.warnings))

    def test_invalid_header_size_signature_and_version(self):
        raw = fixture()
        invalid = {
            "empty": b"",
            "short header": raw[:83],
            "short information": raw[:150],
            "signature": raw[:4] + b"NOPE" + raw[8:],
            "unsupported version": changed_u32(raw, 0, 99),
            "size too small": changed_u32(raw, 12, len(raw) - 1),
            "size too large": changed_u32(raw, 12, len(raw) + 1),
            "trailing bytes": raw + b"extra",
        }
        for name, data in invalid.items():
            with self.subTest(name=name), self.assertRaises(scanner.PrefetchError):
                self.parse(data)

    def test_unknown_v30_layout_is_rejected_instead_of_guessed(self):
        raw = fixture(LAYOUTS[3])
        with self.assertRaises(scanner.PrefetchError):
            self.parse(changed_u32(raw, 84, 0x138))

    def test_invalid_section_and_metric_spans(self):
        raw = fixture()
        strings_start, strings_size = struct.unpack_from("<II", raw, 100)
        invalid = {
            "metrics in header": changed_u32(raw, 84, 80),
            "metrics beyond EOF": changed_u32(raw, 84, len(raw) + 1),
            "metrics count overflow": changed_u32(raw, 88, 0xffffffff),
            "strings in header": changed_u32(raw, 100, 80),
            "strings beyond EOF": changed_u32(raw, 100, len(raw) + 1),
            "strings size overflow": changed_u32(raw, 104, 0xffffffff),
            "sections overlap": changed_u32(raw, 100, 0x130),
            "odd string bytes": changed_u32(raw, 104, strings_size - 1),
            "unaligned filename": changed_u32(raw, 0x130 + 12, 1),
            "filename outside string section": changed_u32(raw, 0x130 + 12, strings_size + 2),
            "filename character count overflow": changed_u32(raw, 0x130 + 16, 0xffffffff),
        }
        for name, data in invalid.items():
            with self.subTest(name=name), self.assertRaises(scanner.PrefetchError):
                self.parse(data)

    def test_embedded_null_reference_is_rejected(self):
        with self.assertRaises(scanner.PrefetchError):
            self.parse(fixture(refs=["C:\\Windows\\SYS\x00TEM32\\SVCHOST.EXE"]))

    def test_executable_name_must_be_basename(self):
        for name in ("", r"C:\SVCHOST.EXE", r"DIR\SVCHOST.EXE"):
            with self.subTest(name=name), self.assertRaises(scanner.PrefetchError):
                self.parse(fixture(executable=name))

    def test_odd_utf16_bytes_are_rejected(self):
        with self.assertRaises(scanner.PrefetchError):
            scanner._utf16(b"A", "test")

    def test_unpaired_surrogates_are_preserved_and_json_escaped(self):
        name = "APP\ud800.EXE"
        reference = "C:\\Evidence\\" + name
        entry = self.parse(fixture(executable=name, refs=[reference]))
        self.assertEqual(entry.executable_name, name)
        self.assertEqual(entry.process_path, reference)
        output = self.directory / "surrogates.json"
        with contextlib.redirect_stdout(io.StringIO()):
            scanner.export_results([entry], [], str(output))
        encoded = output.read_bytes()
        self.assertIn(b"\\ud800", encoded)
        report = json.loads(encoded.decode("utf-8"))
        self.assertEqual(report["entries"][0]["process_path"], reference)

    def test_metric_count_budget(self):
        raw = fixture(refs=[NORMAL_IMAGE, NORMAL_IMAGE])
        with mock.patch.object(scanner, "MAX_METRICS", 1):
            with self.assertRaisesRegex(scanner.PrefetchError, "(?i)budget"):
                self.parse(raw)
        with mock.patch.object(scanner, "MAX_METRICS", 2):
            self.assertEqual(self.parse(raw).process_path, NORMAL_IMAGE)

    def test_per_reference_character_budget(self):
        raw = fixture(refs=[NORMAL_IMAGE])
        characters = len(NORMAL_IMAGE.encode("utf-16-le")) // 2
        with mock.patch.object(scanner, "MAX_REFERENCE_CHARS", characters - 1):
            with self.assertRaisesRegex(scanner.PrefetchError, "(?i)budget"):
                self.parse(raw)
        with mock.patch.object(scanner, "MAX_REFERENCE_CHARS", characters):
            self.assertEqual(self.parse(raw).process_path, NORMAL_IMAGE)

    def test_repeated_reference_slices_consume_cumulative_byte_budget(self):
        raw = bytearray(fixture(refs=[NORMAL_IMAGE] * 3))
        # Repeated references at the identical byte offset still consume work.
        for index in range(3):
            struct.pack_into("<I", raw, 0x130 + index * 32 + 12, 0)
        size = len(NORMAL_IMAGE.encode("utf-16-le"))
        with mock.patch.object(scanner, "MAX_REFERENCE_BYTES", size * 2):
            with self.assertRaisesRegex(scanner.PrefetchError, "(?i)budget"):
                self.parse(bytes(raw))
        with mock.patch.object(scanner, "MAX_REFERENCE_BYTES", size * 3):
            self.assertEqual(self.parse(bytes(raw)).file_references, [NORMAL_IMAGE])

    def test_bounded_read_uses_limit_plus_one_without_stat_race(self):
        class ObservedStream(io.BytesIO):
            def read(self, size=-1):
                self.read_sizes.append(size)
                return super().read(size)

        stream = ObservedStream(bytes(129))
        stream.read_sizes = []
        path = mock.Mock()
        path.open.return_value = stream
        with mock.patch.object(scanner, "MAX_PREFETCH_SIZE", 128):
            with self.assertRaises(scanner.PrefetchError):
                scanner.parse_prefetch_file(path)
        self.assertEqual(stream.read_sizes, [129])
        path.stat.assert_not_called()

    def test_input_exactly_at_read_limit_is_allowed(self):
        raw = fixture()
        with mock.patch.object(scanner, "MAX_PREFETCH_SIZE", len(raw)):
            self.assertEqual(self.parse(raw).run_count, 19)

    def test_source_is_not_modified(self):
        path = self.write(fixture())
        before = path.stat().st_mtime_ns
        raw = path.read_bytes()
        scanner.parse_prefetch_file(path)
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(path.stat().st_mtime_ns, before)

    def test_scan_and_export_preserve_all_entries_and_parse_issues(self):
        self.write(fixture(), "GOOD.PF")
        self.write(fixture(refs=[]), "MISSING.pf")
        self.write(b"malformed", "BAD.pf")
        self.write(b"ignored", "README.txt")
        issues = []
        entries, findings = scanner.scan_prefetch_directory(self.directory, issues)
        self.assertEqual(len(entries), 2)
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["status"], "not_analyzed")
        output = self.directory / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            scanner.export_results(entries, findings, str(output), issues)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["total_entries"], 2)
        self.assertEqual(len(report["entries"]), 2)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["parse_issues"], issues)
        self.assertEqual(report["coverage"]["status"], "partial")
        self.assertTrue(report["limitations"])
        self.assertTrue(all(item["source_sha256"] for item in report["entries"]))

    def test_export_does_not_overwrite_evidence_or_existing_report(self):
        path = self.write(fixture())
        original = path.read_bytes()
        for destination in (path, self.write(b"existing report", "report.json")):
            before = destination.read_bytes()
            with self.subTest(destination=destination.name), self.assertRaises(FileExistsError):
                scanner.export_results([], [], str(destination))
            self.assertEqual(destination.read_bytes(), before)
        self.assertEqual(path.read_bytes(), original)

    def test_empty_scan_exports_missing_evidence_status(self):
        output = self.directory / "empty.json"
        with contextlib.redirect_stdout(io.StringIO()):
            scanner.export_results([], [], str(output))
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["coverage"]["status"], "no_prefetch_evidence")


class MamValidationTests(unittest.TestCase):
    def test_unsupported_and_truncated_headers_are_rejected(self):
        for raw in (b"", b"MAM", b"MAM\x04" + bytes(3),
                    b"MAM\x84" + struct.pack("<I", 100) + bytes(3),
                    b"MAM\x05" + struct.pack("<I", 100) + bytes(32)):
            with self.subTest(raw=raw), self.assertRaises(scanner.PrefetchError):
                scanner.decompress_mam(raw)

    def test_zero_and_oversized_output_are_rejected_before_allocation(self):
        with mock.patch.object(scanner.ctypes, "create_string_buffer") as allocate:
            for size in (0, 0xffffffff):
                with self.subTest(size=size), self.assertRaises(scanner.PrefetchError):
                    scanner.decompress_mam(mam(bytes(32), size))
            allocate.assert_not_called()

    def test_bad_crc_is_rejected_before_native_decompression(self):
        raw = bytearray(mam(b"inert not compressed", 100, crc=True))
        raw[-1] ^= 1
        with self.assertRaisesRegex(scanner.PrefetchError, "(?i)(crc|checksum)"):
            scanner.decompress_mam(bytes(raw))

    @unittest.skipIf(sys.platform == "win32", "non-Windows behavior")
    def test_valid_mam_header_reports_windows_requirement(self):
        for checksum in (False, True):
            with self.subTest(checksum=checksum):
                with self.assertRaisesRegex(scanner.PrefetchError, "(?i)Windows"):
                    scanner.decompress_mam(mam(b"inert bytes", 100, crc=checksum))


@unittest.skipUnless(sys.platform == "win32", "requires real Windows ntdll XPRESS Huffman")
class NativeMamTests(unittest.TestCase):
    # Reuse helpers without inheriting and rerunning portable tests.
    setUp = PrefetchTests.setUp
    write = PrefetchTests.write
    parse = PrefetchTests.parse

    def compress_native(self, raw):
        ntdll = ctypes.WinDLL("ntdll")
        size, fragment = ctypes.c_ulong(), ctypes.c_ulong()
        query = ntdll.RtlGetCompressionWorkSpaceSize
        query.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
        query.restype = ctypes.c_long
        self.assertEqual(query(4, ctypes.byref(size), ctypes.byref(fragment)), 0)
        # Compression requires the first size; decompression uses the fragment size.
        self.assertGreater(size.value, 0)
        self.assertLess(size.value, 64 * 1024 * 1024)
        workspace = ctypes.create_string_buffer(size.value)
        source = ctypes.create_string_buffer(raw)
        output = ctypes.create_string_buffer(len(raw) * 2 + 65536)
        final = ctypes.c_ulong()
        compress = ntdll.RtlCompressBuffer
        compress.argtypes = [ctypes.c_ushort, ctypes.c_void_p, ctypes.c_ulong,
                             ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                             ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
        compress.restype = ctypes.c_long
        status = compress(4, source, len(raw), output, len(output), 4096,
                          ctypes.byref(final), workspace)
        self.assertEqual(status, 0, f"RtlCompressBuffer NTSTATUS {status:#x}")
        self.assertGreater(final.value, 0)
        return output.raw[:final.value]

    def test_native_mam04_and_mam84_roundtrip_and_source_hash(self):
        raw = fixture(LAYOUTS[4])
        compressed = self.compress_native(raw)
        for checksum in (False, True):
            with self.subTest(checksum=checksum):
                packed = mam(compressed, len(raw), crc=checksum)
                self.assertEqual(scanner.decompress_mam(packed), raw)
                entry = self.parse(packed)
                self.assertEqual(entry.version, 30)
                self.assertEqual(entry.run_count, 19)
                self.assertEqual(entry.source_sha256, hashlib.sha256(packed).hexdigest())

    def test_invalid_native_compressed_data_is_rejected(self):
        for payload in (b"", bytes(3), b"\xff" * 256):
            with self.subTest(length=len(payload)), self.assertRaises(scanner.PrefetchError):
                scanner.decompress_mam(mam(payload, 1024))

    def test_native_decompressed_size_mismatch_is_rejected(self):
        raw = fixture()
        compressed = self.compress_native(raw)
        for size in (len(raw) - 1, len(raw) + 1):
            with self.subTest(size=size), self.assertRaises(scanner.PrefetchError):
                scanner.decompress_mam(mam(compressed, size))


if __name__ == "__main__":
    unittest.main()
