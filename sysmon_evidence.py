"""Passive analysis of existing Sysmon XML exports; never touches the event log.

A single Event or Events wrapper (with or without the Windows namespace) is
accepted. Provider and channel are validated. Fields remain observations from
an untrusted export, not a cryptographic assertion of event authenticity.
"""
import hashlib
from pathlib import Path
import xml.etree.ElementTree as ET

MAX_XML_SIZE = 32 * 1024 * 1024
PROVIDER = "Microsoft-Windows-Sysmon"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
RULES = {
    8: ("MEDIUM", "medium", "CreateRemoteThread was recorded; legitimate software also creates remote threads. Empty inferred start fields do not prove injection."),
    10: ("LOW", "low", "ProcessAccess was recorded; an open handle alone does not establish memory writes or injection."),
    25: ("HIGH", "medium", "Sysmon recorded process-image tampering; corroborate the event and investigate the image and context."),
}


def analyze_sysmon_xml(path: Path) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(MAX_XML_SIZE + 1)
    if len(raw) > MAX_XML_SIZE:
        raise ValueError("Sysmon XML exceeds 32 MiB limit; split the export")
    # Normalize supported encodings before the declaration check (UTF-16 must
    # not bypass a raw ASCII-byte check). Reject DTDs/entities entirely.
    try:
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            xml = raw.decode("utf-16")
        elif raw.startswith((b"<\x00", b"\x00<")):
            xml = raw.decode("utf-16-le" if raw[0] else "utf-16-be")
        else:
            xml = raw.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ValueError("Sysmon XML must be UTF-8 or UTF-16") from exc
    if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
        raise ValueError("DTD and entity declarations are not accepted")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed Sysmon XML: {exc}") from exc
    def tag(element):
        value = element.tag
        if value.startswith("{"):
            namespace, value = value[1:].split("}", 1)
            if namespace != NS:
                raise ValueError("Unexpected XML namespace")
        return value
    # Strip only the known event namespace, rejecting foreign nested elements.
    for element in root.iter():
        element.tag = tag(element)
    if root.tag == "Event":
        events = [root]
    elif root.tag == "Events" and all(e.tag == "Event" for e in root):
        events = list(root)
    else:
        raise ValueError("Expected Event or Events XML export")
    result = {"source_path": str(path), "source_sha256": hashlib.sha256(raw).hexdigest(),
              "events_total": len(events), "events_supported": 0, "events_ignored": 0,
              "findings": [], "issues": [],
              "limitations": "Source exports may be incomplete or altered. No PID-only or Prefetch-name correlation is performed. Absence of events does not rule out compromise."}
    for index, event in enumerate(events, 1):
        system = event.find("System")
        provider = system.find("Provider") if system is not None else None
        record = system.findtext("EventRecordID") if system is not None else None
        if provider is None or provider.get("Name") != PROVIDER or system.findtext("Channel") != CHANNEL:
            result["issues"].append({"event_index": index, "record_id": record, "error": "Missing or unexpected Sysmon provider/channel"})
            continue
        try:
            event_id = int(system.findtext("EventID", ""))
        except ValueError:
            result["issues"].append({"event_index": index, "record_id": record, "error": "Invalid EventID"})
            continue
        if event_id not in RULES:
            result["events_ignored"] += 1
            continue
        data = event.find("EventData")
        fields = {}
        duplicate = False
        if data is not None:
            for node in data.findall("Data"):
                key = node.get("Name", "").casefold()
                if not key or key in fields:
                    duplicate = True
                fields[key] = node.text or ""
        required = ("processguid", "image", "type") if event_id == 25 else ("sourceprocessguid", "targetprocessguid", "sourceimage", "targetimage")
        if duplicate or any(not fields.get(name) for name in required):
            result["issues"].append({"event_index": index, "record_id": record, "error": "Missing or duplicate required event fields"})
            continue
        severity, confidence, reason = RULES[event_id]
        result["events_supported"] += 1
        result["findings"].append({"event_id": event_id, "record_id": record,
            "event_index": index, "computer": system.findtext("Computer"),
            "utc_time": fields.get("utctime") or (system.find("TimeCreated").get("SystemTime") if system.find("TimeCreated") is not None else None),
            "severity": severity, "confidence": confidence, "evidence_type": "sysmon_recorded_event",
            "reason": reason, "fields": fields})
    return result
