# Benign synthetic evidence tests

Run from the repository root with `python -m unittest discover -v`.
The suite uses only the Python standard library and temporary files. It does not
read live host evidence, run fixture contents, install Sysmon, or modify settings.

`test_prefetch.py` constructs inert SCCA records in memory. The literal offsets
cover versions 17, 23, 26, both version-30 variants, and version 31, independently
of the scanner's layout table. Fields intentionally include multiple metrics,
nonzero byte offsets into UTF-16 strings, raw submicrosecond FILETIMEs, malformed
spans, and adversarial repeated references. These are focused parser fixtures,
not captures from Windows and not a substitute for validation against preserved
real-world forensic samples.

Format references:

- [libscca format specification](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc)
- [libscca layout selection](https://github.com/libyal/libscca/blob/main/libscca/libscca_file_information.c)
- [MAM checksum research and implementation](https://gist.github.com/dfirfpi/113ff71274a97b489dfd)

Three native MAM tests run only on Windows. They generate compressed data using
the real `ntdll.RtlCompressBuffer` with XPRESS Huffman (algorithm 4), explicitly
query its compression workspace, then exercise the scanner's actual native
decompressor for MAM04 and CRC-bearing MAM84. They also check invalid compressed
streams and inconsistent declared output sizes. Their skips on Linux/macOS are
intentional and must not be reported as native decompression passing.
