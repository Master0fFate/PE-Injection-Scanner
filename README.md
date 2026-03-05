# PE Injection Detector

A specialized digital forensics and incident response (DFIR) tool designed to detect potential process hollowing and PE injection artifacts by auditing the Windows Prefetch system.

## Overview

This tool analyzes Windows Prefetch (.pf) files to identify anomalies often associated with stealthy code execution. It cross-references executable metadata against expected system paths and known injection targets. By leveraging the Windows Prefetch architecture, the scanner can identify historical execution traces of hollowed processes even after the malicious process has terminated.

Key detection vectors:
- Process path mismatches (e.g., svchost.exe running from a non-System32 directory).
- Missing file references in prefetch metrics.
- High-risk target auditing for common targets of process hollowing (RuntimeBroker, Ctfmon, etc.).
- MAM decompression support for modern Windows 10/11 prefetch formats.

## Requirements

- Operating System: Windows (Required for Prefetch architecture and Win32 Console API).
- Python Version: Python 3.10 or higher.
- Privileges: Administrator shell (Required to read the C:\Windows\Prefetch directory).

## Usage Walkthrough

### 1. Basic Scan
To perform a standard scan of the local system, run the script from an elevated command prompt:

```powershell
python pe_injection_scan.py
```

### 2. Exporting Results
You can export the results of the scan to a JSON file for further analysis or integration with other security tools:

```powershell
python pe_injection_scan.py --export report.json
```

### 3. Displaying All Entries
By default, the tool only shows flagged findings. Use the --all flag to see every prefetch entry analyzed:

```powershell
python pe_injection_scan.py --all
```

### 4. Custom Prefetch Directory
If analyzing an offline image or a forensically recovered folder, specify the path manually:

```powershell
python pe_injection_scan.py --prefetch-dir D:\Forensics\Dumps\Prefetch
```

## Building as a Portable Executable

The project includes a PyInstaller .spec file configured for standalone builds. The resulting EXE includes a UAC manifest to automatically request admin privileges.

```powershell
pip install pyinstaller
pyinstaller --clean --upx-dir "C:\path\to\upx" pe_injection_scan.spec
```

The output will be located in the dist folder.