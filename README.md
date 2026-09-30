# PE Evidence Triage

Read-only DFIR triage of Windows Prefetch and existing Sysmon XML exports. The
repository and script keep their original names for compatibility.

Prefetch records historical execution-related references. An unexpected path or
missing executable reference is a lead, **not proof of PE injection or process
hollowing**. This tool does not inspect process memory, establish a clean host,
or determine who injected into a process. Corroborate findings with trusted
telemetry and forensic evidence.

## What it analyzes

- Prefetch versions 17, 23, 26, both documented v30 layouts, and v31
- Version-correct file metrics, run counts and up to eight historical run times
- Ambiguous/missing executable references and unusual locations for selected
  Windows executables, labeled low-confidence heuristics
- Existing Sysmon event 8 (remote thread), 10 (process access), and 25 (process
  tampering) XML records, with provider/channel validation and original fields
- Corrupt/unsupported files as explicit coverage gaps, never silently clean
- SHA-256 provenance, source paths, all parsed entries, timestamps, parse issues,
  evidence type and confidence in versioned JSON reports

Sysmon event 25 is stronger telemetry than a Prefetch path clue, but still
requires corroboration. Event 10 alone does not establish a memory write; event
8 also occurs in legitimate software. Sysmon findings are kept separate from
Prefetch: names or reused PIDs cannot reliably identify the same process.

## Requirements

Python 3.10+; no third-party runtime packages. Uncompressed Prefetch and Sysmon
XML work offline on Windows, Linux and macOS. MAM04/MAM84 XPRESS-Huffman
compression uses native Windows decompression and is explicitly reported as
unsupported on other platforms. Access to the live Windows Prefetch directory
may require elevation; copied evidence does not inherently require admin.

## Usage

```powershell
# Local Prefetch (Windows)
python pe_injection_scan.py --no-pause

# Offline evidence; export path must be NEW to avoid overwriting evidence
python pe_injection_scan.py --prefetch-dir D:\Evidence\Prefetch --all --export report.json --no-pause

# Existing Sysmon XML export, alone or alongside --prefetch-dir
python pe_injection_scan.py --sysmon-xml D:\Evidence\sysmon.xml --export events-report.json --no-pause

# Automation
python pe_injection_scan.py --prefetch-dir ./fixtures --no-banner --no-pause --export report.json
```

XML input must be a single `Event` or an `Events` wrapper, UTF-8 or UTF-16, with
Microsoft-Windows-Sysmon provider and Microsoft-Windows-Sysmon/Operational
channel. Binary EVTX is not supported. The tool never installs/configures Sysmon,
changes the host, opens processes, launches referenced executables or retrieves
malware. It reads input files and only writes the explicitly requested report.
Filesystem access may still have ordinary operating-system access-time effects;
use forensic copies/read-only media when preservation is required.

Exit codes: `0` analysis completed (findings may exist), `1` input/output failure,
`2` partial/no Prefetch analysis or rejected Sysmon records. Inspect JSON coverage
and Sysmon event counts even after exit 0: events outside IDs 8/10/25 are counted
as ignored. An empty event export is not assurance of safety. Flags `--all`,
`--no-banner` and `--no-pause` remain supported. Noninteractive execution never
waits for a key.

## Testing and building

```powershell
python -m unittest discover -s tests -v
python -m compileall -q pe_injection_scan.py sysmon_evidence.py
# Optional standalone build, using the supplied file's exact name
python -m pip install pyinstaller
python -m PyInstaller --clean PE_INJECTION_SCAN.spec
```

CI runs Python 3.10 and 3.13 on Windows and Ubuntu. Fixtures are deterministic,
synthetic, and benign; the Windows tests exercise native compression and
decompression without executing fixture contents. No malware samples or live
host experiments are used. The existing executable specification requests UAC
elevation; run the Python CLI without elevation for accessible offline evidence.

See [evidence model, sources and limits](docs/evidence-model.md). Schema version
2 expands the original finding-only export to include every parsed record and
coverage issues; downstream consumers must account for the changed schema.
