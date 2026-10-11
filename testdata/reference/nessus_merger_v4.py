#!/usr/bin/env python3
"""
Nessus File Merger v3
---------------------
Merges multiple .nessus (NessusClientData_v2) files into a single Combined.nessus.

Usage:
  python3 merger-v3.py [output_filename] [directory]

  output_filename : optional, default "Combined.nessus"
  directory       : optional, default "." (current directory)
"""

import io
import os
import re
import sys
import xml.etree.ElementTree as ET
import xml.sax
from copy import deepcopy

# ── Config ───────────────────────────────────────────────────────────────────
SKIP_PLUGINS_IN_SECONDARY = {"19506"}   # Nessus Scan Information — keep only from primary
OUTPUT_DEFAULT = "Combined.nessus"

# XML 1.0 legal character ranges per spec
_ILLEGAL_XML_RE = re.compile(
    r'[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]'
)

# ── XML repair pipeline ───────────────────────────────────────────────────────

class _NullSAXHandler(xml.sax.ContentHandler):
    pass


def _sax_valid(xml_bytes):
    try:
        xml.sax.parseString(xml_bytes, _NullSAXHandler())
        return True
    except xml.sax.SAXParseException:
        return False


def repair_xml_bytes(xml_bytes):
    """
    Attempt to repair serialized XML bytes that fail SAX validation.
    Applies fixes in order, re-validating after each step.
    Returns repaired bytes if successful, raises ValueError if unrecoverable.

    Repair steps:
      1. Strip UTF-8 BOM
      2. Remove duplicate XML declarations
      3. Strip illegal XML 1.0 control characters from text content
      4. Escape bare & that survived serialization
      5. Truncation check — unrecoverable, raises with clear message
    """
    repaired = xml_bytes

    # Step 1: UTF-8 BOM
    if repaired.startswith(b'\xef\xbb\xbf'):
        repaired = repaired[3:]
        print("  [repair] Stripped UTF-8 BOM")
        if _sax_valid(repaired):
            return repaired

    # Step 2: Duplicate XML declarations
    decl_re = re.compile(rb'<\?xml[^?]*\?>', re.IGNORECASE)
    declarations = list(decl_re.finditer(repaired))
    if len(declarations) > 1:
        body_start = declarations[1].start()
        repaired = repaired[:body_start] + decl_re.sub(b'', repaired[body_start:])
        print(f"  [repair] Removed {len(declarations) - 1} duplicate XML declaration(s)")
        if _sax_valid(repaired):
            return repaired

    # Step 3: Illegal XML 1.0 characters
    try:
        text = repaired.decode('utf-8', errors='replace')
        cleaned = _ILLEGAL_XML_RE.sub('', text)
        if cleaned != text:
            removed = len(text) - len(cleaned)
            repaired = cleaned.encode('utf-8')
            print(f"  [repair] Stripped {removed} illegal XML 1.0 character(s)")
            if _sax_valid(repaired):
                return repaired
    except Exception as e:
        print(f"  [repair] Illegal char strip failed: {e}")

    # Step 4: Bare ampersands
    try:
        text = repaired.decode('utf-8', errors='replace')
        fixed = re.sub(
            r'&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)',
            '&amp;',
            text
        )
        if fixed != text:
            count = fixed.count('&amp;') - text.count('&amp;')
            repaired = fixed.encode('utf-8')
            print(f"  [repair] Escaped {count} bare ampersand(s)")
            if _sax_valid(repaired):
                return repaired
    except Exception as e:
        print(f"  [repair] Ampersand fix failed: {e}")

    # Step 5: Truncation check
    if not repaired.strip().endswith(b'</NessusClientData_v2>'):
        raise ValueError(
            "Output XML is truncated (missing closing </NessusClientData_v2> tag). "
            "Likely an out-of-memory condition on a very large merge. "
            "Try merging fewer files at once."
        )

    raise ValueError(
        "Unable to repair XML — unknown failure mode. "
        "Run with a single source file to isolate which input is corrupt."
    )


# ── Merge helpers ─────────────────────────────────────────────────────────────

def item_key(item):
    """
    Unique key: (pluginID, port, protocol, plugin_output_hash).
    Including plugin_output_hash preserves legitimately distinct findings
    that share the same pluginID/port/protocol (e.g. Service Detection on
    the same port with different banners) while deduplicating true duplicates.
    """
    output = (item.findtext("plugin_output") or "").strip()
    return (
        item.attrib.get("pluginID", ""),
        item.attrib.get("port", ""),
        item.attrib.get("protocol", ""),
        hash(output),
    )


def merge_host_properties(base_hp, new_hp):
    """Union-merge HostProperties tags — no overwrites, no duplicates."""
    existing_names = {t.attrib.get("name") for t in base_hp.findall("tag")}
    for tag in new_hp.findall("tag"):
        name = tag.attrib.get("name")
        if name and name not in existing_names:
            base_hp.append(deepcopy(tag))
            existing_names.add(name)


def collect_nessus_files(directory):
    """Sorted list of .nessus paths in directory, excluding the output file."""
    return sorted(
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if f.lower().endswith(".nessus") and f != OUTPUT_FILE
    )


def parse_file(path):
    """Parse a .nessus file; return ElementTree or None on failure."""
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        if root.tag != "NessusClientData_v2":
            print(f"  [WARN] Unexpected root tag '{root.tag}', skipping.")
            return None
        if root.find("Report") is None:
            print(f"  [WARN] No <Report> element found, skipping.")
            return None
        return tree
    except ET.ParseError as e:
        print(f"  [ERROR] XML parse error: {e}")
        return None


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global OUTPUT_FILE

    OUTPUT_FILE = sys.argv[1] if len(sys.argv) > 1 else OUTPUT_DEFAULT
    scan_dir    = sys.argv[2] if len(sys.argv) > 2 else "."

    nessus_files = collect_nessus_files(scan_dir)
    if not nessus_files:
        print("[!] No .nessus files found.")
        sys.exit(1)

    print(f"[*] Found {len(nessus_files)} .nessus file(s) in '{scan_dir}'")
    print(f"[*] Output → {OUTPUT_FILE}\n")

    # ── Primary ───────────────────────────────────────────────────────────────
    primary_path = nessus_files[0]
    print(f"[+] Primary: {os.path.basename(primary_path)}")

    main_tree = parse_file(primary_path)
    if main_tree is None:
        print("[!] Primary file failed to parse. Aborting.")
        sys.exit(1)

    main_root   = main_tree.getroot()
    main_report = main_root.find("Report")
    main_report.attrib["name"] = "Combined Report"

    host_index = {}
    for rh in main_report.findall("ReportHost"):
        if not rh.attrib.get("name"):
            print("  [WARN] ReportHost missing name attrib in primary, removing.")
            main_report.remove(rh)
            continue
        host_index[rh.attrib["name"]] = rh

    item_index = {
        name: {item_key(i) for i in rh.findall("ReportItem")}
        for name, rh in host_index.items()
    }

    print(f"    Hosts: {len(host_index)}  |  Items: {sum(len(v) for v in item_index.values())}")

    # ── Secondaries ───────────────────────────────────────────────────────────
    total_new_hosts = 0
    total_new_items = 0

    for path in nessus_files[1:]:
        print(f"\n[+] Merging: {os.path.basename(path)}")
        tree = parse_file(path)
        if tree is None:
            continue

        report    = tree.getroot().find("Report")
        new_hosts = 0
        new_items = 0

        for rh in report.findall("ReportHost"):
            host_name = rh.attrib.get("name")
            if not host_name:
                print("  [WARN] ReportHost missing name attrib, skipping.")
                continue

            if host_name not in host_index:
                new_rh = deepcopy(rh)
                main_report.append(new_rh)
                host_index[host_name] = new_rh
                item_index[host_name] = {item_key(i) for i in new_rh.findall("ReportItem")}
                new_hosts += 1
                new_items += len(item_index[host_name])
            else:
                base_rh = host_index[host_name]
                base_hp = base_rh.find("HostProperties")
                new_hp  = rh.find("HostProperties")
                if base_hp is not None and new_hp is not None:
                    merge_host_properties(base_hp, new_hp)
                elif base_hp is None and new_hp is not None:
                    base_rh.insert(0, deepcopy(new_hp))

                for item in rh.findall("ReportItem"):
                    if item.attrib.get("pluginID") in SKIP_PLUGINS_IN_SECONDARY:
                        continue
                    k = item_key(item)
                    if k not in item_index[host_name]:
                        base_rh.append(deepcopy(item))
                        item_index[host_name].add(k)
                        new_items += 1

        print(f"    New hosts: {new_hosts}  |  New items: {new_items}")
        total_new_hosts += new_hosts
        total_new_items += new_items

    # ── Serialize into memory ─────────────────────────────────────────────────
    output_path = os.path.join(scan_dir, OUTPUT_FILE)
    tmp_path    = output_path + ".tmp"

    if hasattr(ET, "indent"):
        ET.indent(main_tree, space="  ")

    buf = io.BytesIO()
    buf.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
    try:
        main_tree.write(buf, encoding="UTF-8", xml_declaration=False)
    except Exception as e:
        print(f"[!] Serialization failed: {e}")
        sys.exit(1)
    xml_bytes = buf.getvalue()

    # ── Validate — auto-repair if needed ─────────────────────────────────────
    if not _sax_valid(xml_bytes):
        print("[!] Output XML failed SAX validation — attempting auto-repair...")
        try:
            xml_bytes = repair_xml_bytes(xml_bytes)
            print("[✓] Repair succeeded — output is clean")
        except ValueError as e:
            print(f"[!] Repair failed: {e}")
            print("    No output file written.")
            sys.exit(1)
    
    # ── Write: fsync to .tmp then atomic rename ───────────────────────────────
    try:
        with open(tmp_path, "wb") as fh:
            fh.write(xml_bytes)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception as e:
        print(f"[!] Disk write failed: {e}")
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        sys.exit(1)

    os.replace(tmp_path, output_path)

    final_hosts = len(host_index)
    final_items = sum(len(v) for v in item_index.values())

    print(f"\n[✓] Written: {output_path}")
    print(f"    Total hosts : {final_hosts}  (+{total_new_hosts} merged)")
    print(f"    Total items : {final_items}  (+{total_new_items} merged)")


if __name__ == "__main__":
    main()