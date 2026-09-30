"""Exercise only benign synthetic evidence through the actual packaged binary."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_prefetch import fixture
from tests.test_sysmon import event


def main():
    executable = Path(sys.argv[1]).resolve()
    if not executable.is_file():
        raise RuntimeError(f"Missing executable: {executable}")
    subprocess.run([str(executable), '--help'], check=True, timeout=60)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        evidence = root / 'Prefetch'
        evidence.mkdir()
        (evidence / 'SYNTHETIC.pf').write_bytes(fixture())
        xml = root / 'events.xml'
        xml.write_text(event(), encoding='utf-8')
        report = root / 'report.json'
        subprocess.run([str(executable), '--prefetch-dir', str(evidence),
                        '--sysmon-xml', str(xml), '--export', str(report),
                        '--no-banner', '--no-pause'], check=True, timeout=60)
        result = json.loads(report.read_text(encoding='utf-8'))
        if result['total_entries'] != 1 or result['sysmon']['events_supported'] != 1:
            raise RuntimeError('Packaged binary did not analyze both fixture sources')
        if result['parse_issues'] or result['sysmon']['issues']:
            raise RuntimeError('Packaged binary rejected valid synthetic evidence')
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    executable.with_suffix('.exe.sha256').write_text(f'{digest}  {executable.name}\n', encoding='ascii')
    print(f'Packaged executable smoke passed; SHA-256 {digest}')


if __name__ == '__main__':
    main()
