import os
import re
import datetime
from collections import defaultdict
from html import escape

def load_description_map(txt_file_path):
    desc_map = {}
    with open(txt_file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.lower().startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 5:
                continue
            tc_id = parts[0].strip()
            description = parts[1].strip()
            sid = parts[2].strip().replace("0x", "").upper()
            sub = parts[3].strip().replace("0x", "").upper()
            positive_response = parts[4].strip().replace("0x", "").upper()
            key = (sid, sub)
            value = (description, tc_id, positive_response)
            if key not in desc_map:
                desc_map[key] = []
            desc_map[key].append(value)
    return desc_map

def parse_data_bytes(line):
    """Auto-detect CAN or CANFD and extract data bytes."""
    match = re.search(r'd\s+\d+\s+((?:[0-9A-Fa-f]{2}\s+)+)', line)
    if match:
        return match.group(1).strip().split()

    tokens = line.strip().split()
    for i in range(len(tokens) - 11):
        if tokens[i:i+4] == ['1', '0', '8', '8']:
            data_bytes = tokens[i+4:i+12]
            if all(len(b) == 2 and all(c in '0123456789ABCDEFabcdef' for c in b) for b in data_bytes):
                return data_bytes

    return []

def get_description(data_bytes):
    if not data_bytes or len(data_bytes) < 2:
        return "", "", ""
    sid_index = 2 if data_bytes[0].startswith("1") else 1
    if len(data_bytes) <= sid_index:
        return "", "", ""
    sid = data_bytes[sid_index].upper()

    for length in (3, 2, 1):
        if sid_index + length < len(data_bytes):
            sub = ''.join(data_bytes[sid_index + 1: sid_index + 1 + length]).upper()
            key = (sid, sub)
            if key in DESCRIPTION_MAP:
                used = getattr(get_description, "used_tc_ids", set())
                for desc, tc_id, expected_resp in DESCRIPTION_MAP[key]:
                    if tc_id not in used:
                        used.add(tc_id)
                        setattr(get_description, "used_tc_ids", used)
                        return desc, tc_id, expected_resp
                return DESCRIPTION_MAP[key][0]

    key_sid_only = (sid, "")
    if key_sid_only in DESCRIPTION_MAP:
        used = getattr(get_description, "used_tc_ids", set())
        for desc, tc_id, expected_resp in DESCRIPTION_MAP[key_sid_only]:
            if tc_id not in used:
                used.add(tc_id)
                setattr(get_description, "used_tc_ids", used)
                return desc, tc_id, expected_resp
        return DESCRIPTION_MAP[key_sid_only][0]

    return "", "", ""

def parse_line(line):
    line = line.strip()
    if not line or " d " not in line:
        return None
    parts = line.split()

    try:
        timestamp = float(parts[0])
    except:
        return None

    direction = parts[3]
    can_id = parts[4].upper()
    data_bytes = parse_data_bytes(line)

    return {
        "timestamp": timestamp,
        "can_id": can_id,
        "direction": direction,
        "data_bytes": data_bytes,
        "raw": line
    }

# Rest of the code remains unchanged
