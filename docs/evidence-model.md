# Evidence model and support boundaries

## Interpretations

- `process_path` is a uniquely matching **file metric reference**, not an
  authoritative process-image mapping. Exact Windows basename equality avoids
  mistaking `evilnotepad.exe` for `notepad.exe`. Multiple matches remain ambiguous.
- Prefetch findings are low-confidence triage. No metric-reference match may be
  explained by incomplete artifacts or the 29-character header-name limit.
- Common-location rules accept System32 and SysWOW64 suffixes. Custom Windows
  roots, servicing, legitimate copies and other installations still require
  review. Notepad and Spotify have no fixed-location rule because installation
  methods vary. Location matching is not signature/trust verification.
- `NO_ANOMALY` means these limited heuristics did not flag the record. It is never
  a statement that an executable or host is clean.
- Source SHA-256 hashes identify the bytes analyzed, not their authenticity.
  Filesystem timestamps describe the supplied evidence copy. POSIX ctime is not
  reported as creation time. Raw FILETIMEs are retained even if not representable
  as a Python datetime; displayed dates are UTC and zero means unset.
- XML is untrusted recorded telemetry. Provider/channel labels are checked but
  cannot authenticate a copied export. GUID field names are normalized
  case-insensitively; original source/target roles and fields are preserved.
  Event 25 has no inferred initiator. No PID-only or name-only joins are made.

## Binary format evidence

Microsoft does not publish a complete Prefetch binary format contract. Layouts
follow the primary libscca implementation and its reverse-engineered format
specification, not an invented Microsoft guarantee:

- [libscca PF format specification](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc)
- [libscca information parser](https://github.com/libyal/libscca/blob/main/libscca/libscca_file_information.c)
- [libscca structure definitions](https://github.com/libyal/libscca/blob/main/libscca/scca_file_information.h)
- [Original Windows 10 MAM research](https://blog.digital-forensics.it/2015/06/a-first-look-at-windows-10-prefetch.html)
- [Original checksum/decompression implementation](https://gist.github.com/dfirfpi/113ff71274a97b489dfd)

Absolute SCCA offsets: metrics start/count at 0x54/0x58; filename strings
start/length at 0x64/0x68. v17 metrics are 20 bytes with filename offset/character
count at entry+8/+12. Later metrics are 32 bytes with entry+12/+16. Filename
offsets are bytes relative to the bounded string section; character counts are
UTF-16 code units. Unpaired surrogate code units are preserved and JSON escaped.

v17 runtime/count offsets are 0x78/0x90; v23 0x80/0x98; v26 0x80/0xD0. v30
with metrics starting 0x130 uses count 0xD0; metrics starting 0x128 uses count
0xC8. v31 supports the latter layout only. v26+ retain eight runtime slots.
Unknown versions/layouts and malformed ranges are reported, not guessed.

MAM04 has an eight-byte wrapper; MAM84 has a twelve-byte checksum wrapper. The
latter CRC32 covers the whole compressed file with checksum bytes zeroed. The
advertised uncompressed size and actual native decompression output must agree.

## Official Windows telemetry and API references

- [Microsoft Sysmon event documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft Sysmon manifest](https://github.com/microsoft/SysmonCommon/blob/main/manifest.xml)
- [RtlDecompressBufferEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbufferex)
- [RtlGetCompressionWorkSpaceSize](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetcompressionworkspacesize)

Sysmon 8 records remote-thread creation; empty StartModule/StartFunction fields
are inferred-field limitations, not proof of maliciousness. Sysmon 10 records a
process open and has benign diagnostic uses. Sysmon 25 records image tampering
associated with hiding techniques such as hollowing and herpaderping. Confidence
labels are qualitative analyst priorities, not calibrated probabilities.

## Resource and validation limits

Per Prefetch file: 50 MiB input, 64 MiB decompressed, 50,000 metric records,
32,768 UTF-16 code units per reference, and 16 MiB cumulative reference bytes
including repeated/overlapping slices. A budget excess rejects the record with
an explicit coverage error rather than truncating evidence. Set-based
reference deduplication avoids quadratic comparisons. Sections must fit their
declared boundaries and the declared file size must match. Strict validation
may reject recoverable damaged evidence; use specialist recovery tools and
preserve originals rather than treating rejection as maliciousness.

Sysmon XML is limited to 32 MiB, rejects DTD/entity declarations (including
UTF-16 forms), and supports only the documented event namespace or no namespace.
Split larger exports externally. Unsupported event IDs are counted but ignored.
The parser does not validate forensic chain of custody or reconstruct lost logs.

Tests cover synthetic structural and adversarial cases and native Windows MAM
roundtrips. They do not establish detection sensitivity/specificity on a real
incident corpus, all Windows builds, packed executable behavior, or actual
process hollowing. Packaging and live-host operational behavior need separate
validation; no sample execution is required or performed here.
