import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import sysmon_evidence as se


def event(event_id=25, provider=se.PROVIDER, channel=se.CHANNEL, fields=None, namespace=True):
    if fields is None:
        fields = {'ProcessGuid': '{synthetic-process}', 'Image': r'C:\Windows\System32\notepad.exe', 'Type': 'Image is replaced'}
    ns = f' xmlns="{se.NS}"' if namespace else ''
    data = ''.join(f'<Data Name="{key}">{value}</Data>' for key, value in fields.items())
    return f'<Event{ns}><System><Provider Name="{provider}"/><EventID>{event_id}</EventID><EventRecordID>42</EventRecordID><Channel>{channel}</Channel><Computer>fixture-host</Computer><TimeCreated SystemTime="2026-01-02T03:04:05Z"/></System><EventData>{data}</EventData></Event>'


class SysmonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'evidence.xml'

    def analyze(self, content):
        self.path.write_bytes(content if isinstance(content, bytes) else content.encode())
        return se.analyze_sysmon_xml(self.path)

    def test_tampering_preserves_source_and_does_not_invent_initiator(self):
        result = self.analyze(event())
        finding = result['findings'][0]
        self.assertEqual(finding['severity'], 'HIGH')
        self.assertEqual(finding['confidence'], 'medium')
        self.assertNotIn('sourceprocessguid', finding['fields'])
        self.assertEqual(finding['record_id'], '42')
        self.assertEqual(len(result['source_sha256']), 64)

    def test_guid_capitalizations_and_low_access_confidence(self):
        for event_id, suffix, severity in [(8, 'Guid', 'MEDIUM'), (10, 'GUID', 'LOW')]:
            fields = {f'SourceProcess{suffix}': '{source}', f'TargetProcess{suffix}': '{target}',
                      'SourceImage': 'debugger.exe', 'TargetImage': 'app.exe', 'StartModule': ''}
            result = self.analyze(event(event_id, fields=fields))
            self.assertEqual(result['findings'][0]['fields']['sourceprocessguid'], '{source}')
            self.assertEqual(result['findings'][0]['severity'], severity)

    def test_provider_and_channel_required(self):
        for kwargs in ({'provider': 'Other'}, {'channel': 'System'}):
            result = self.analyze(event(**kwargs))
            self.assertEqual(len(result['issues']), 1)
            self.assertEqual(result['findings'], [])

    def test_missing_and_duplicate_fields(self):
        for xml in (event(fields={}), event().replace('</EventData>', '<Data Name="processguid">duplicate</Data></EventData>')):
            self.assertEqual(len(self.analyze(xml)['issues']), 1)

    def test_wrapper_single_namespaced_and_utf16(self):
        for xml in (event(), event(namespace=False), '<Events>'+event()+event(1)+'</Events>', event().encode('utf-16')):
            self.assertEqual(len(self.analyze(xml)['findings']), 1)

    def test_rejects_entities_in_both_encodings(self):
        xml = '<!DOCTYPE Event [<!ENTITY sample "expansion">]>' + event()
        for content in (xml, xml.encode('utf-16')):
            with self.assertRaisesRegex(ValueError, 'DTD'):
                self.analyze(content)

    def test_malformed_foreign_namespace_and_size(self):
        for content in ('<Event>', '<Something/>', event().replace(se.NS, 'https://invalid.example')):
            with self.assertRaises(ValueError):
                self.analyze(content)
        with patch.object(se, 'MAX_XML_SIZE', 10):
            with self.assertRaisesRegex(ValueError, 'limit'):
                self.analyze(event())

    def test_no_events_or_unrelated_events_are_explicit(self):
        result = self.analyze('<Events>'+event(1)+'</Events>')
        self.assertEqual(result['events_ignored'], 1)
        self.assertEqual(result['findings'], [])
        self.assertEqual(self.analyze('<Events/>')['events_total'], 0)

    def test_cli_sysmon_only_exports_and_respects_existing_report(self):
        self.analyze(event())
        report = Path(self.temp.name) / 'report.json'
        command = [sys.executable, 'pe_injection_scan.py', '--sysmon-xml', str(self.path),
                   '--export', str(report), '--no-banner', '--no-pause']
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(report.read_text())
        self.assertEqual(data['sysmon']['events_supported'], 1)
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)


if __name__ == '__main__':
    unittest.main()
