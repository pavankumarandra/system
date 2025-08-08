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
    match = re.search(r'd\s+\d+\s+((?:[0-9A-Fa-f]{2}\s+)+)', line)
    if match:
        return match.group(1).strip().split()
    return []

def get_description(data_bytes, timestamp):
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
    return "", "", ""

def get_failure_reason(nrc):
    nrc_dict = {
        "10": "generalReject",
        "11": "serviceNotSupported",
        "12": "subFunctionNotSupported",
        "13": "incorrectMessageLengthOrInvalidFormat",
        "14": "responseTooLong",
        "21": "busyRepeatRequest",
        "22": "conditionsNotCorrect",
        "23": "ISOSAEReserved",
        "24": "requestSequenceError",
        "31": "requestOutOfRange",
        "33": "securityAccessDenied",
        "35": "invalidKey",
        "36": "exceedNumberOfAttempts",
        "37": "requiredTimeDelayNotExpired",
        "70": "uploadDownloadNotAccepted",
        "71": "transferDataSuspended",
        "72": "generalProgrammingFailure",
        "73": "wrongBlockSequenceCounter",
        "78": "ResponsePending",
        "7E": "subFunctionNotSupportedInActiveSession",
        "7F": "serviceNotSupportedInActiveSession",
        "81": "rpmTooHigh",
        "82": "rpmTooLow",
        "83": "engineIsRunning",
        "84": "engineIsNotRunning",
        "85": "engineRunTimeTooLow",
        "86": "temperatureTooHigh",
        "87": "temperatureTooLow",
        "88": "vehicleSpeedTooHigh",
        "89": "vehicleSpeedTooLow",
        "8A": "throttle/PedalTooHigh",
        "8B": "throttle/PedalTooLow",
        "90": "shifterLeverNotInPark",
        "91": "torqueConverterClutchLocked",
        "92": "voltageTooHigh",
        "93": "voltageTooLow",
    }
    return nrc_dict.get(nrc.upper(), f"Unknown NRC: {nrc}")

def get_status(data_bytes, expected_resp):
    if not data_bytes or len(data_bytes) < 3:
        return "Fail", "Incomplete response"

    if data_bytes[0].upper() == "10":
        actual_sid = data_bytes[2].upper()
    else:
        actual_sid = data_bytes[1].upper()

    if actual_sid == "7F":
        if len(data_bytes) >= 4 and data_bytes[3].upper() == "78":
            return "Pending", ""
        nrc = data_bytes[3].upper()
        if nrc == expected_resp:
            return "Pass", ""
        else:
            return "Fail", get_failure_reason(nrc)

    if actual_sid == expected_resp:
        return "Pass", ""

    return "Fail", f"Unexpected response: {actual_sid}"

def parse_line(line):
    line = line.strip()
    if not line or "d" not in line:
        return None
    parts = line.split()
    if len(parts) < 5:
        return None
    try:
        timestamp = float(parts[0])
    except ValueError:
        return None
    can_id = parts[2]
    direction = parts[3]
    data_bytes = parse_data_bytes(line)
    if direction == "Tx":
        desc, tc_id, expected_resp = get_description(data_bytes, timestamp)
        msg = {
            "timestamp": timestamp,
            "can_id": can_id,
            "direction": direction,
            "data_bytes": data_bytes,
            "desc": desc,
            "tc_id": tc_id,
            "expected_resp": expected_resp,
            "status": "Pending"
        }
        return msg
    elif direction == "Rx":
        return {
            "timestamp": timestamp,
            "can_id": can_id,
            "direction": direction,
            "data_bytes": data_bytes
        }
    return None

def parse_asc_file(asc_file_path, allowed_tx_ids, allowed_rx_ids):
    messages_by_tc = defaultdict(list)
    current_request = None
    start_ts = None
    end_ts = None
    awaiting_multiframe = False
    skip_next_fc = False
    rx_multi_response_pending = False
    rx_multi_response_first = None

    allowed_tx_ids = set(id.upper() for id in allowed_tx_ids)
    allowed_rx_ids = set(id.upper() for id in allowed_rx_ids)

    with open(asc_file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or not re.match(r"^\d+\.\d+", line):
                continue

            msg = parse_line(line)
            if not msg:
                continue

            can_id = msg["can_id"].upper()

            if msg["direction"] == "Tx" and can_id in allowed_tx_ids:
                data_bytes = msg["data_bytes"]
                if data_bytes and data_bytes[0].upper() == "10":
                    current_request = msg
                    awaiting_multiframe = True
                    skip_next_fc = True
                else:
                    if msg.get("tc_id") and msg.get("desc"):
                        current_request = msg
                        awaiting_multiframe = False

            elif msg["direction"] == "Rx" and can_id in allowed_rx_ids:
                data_bytes = msg["data_bytes"]

                if skip_next_fc and data_bytes and data_bytes[0].upper() == "30":
                    skip_next_fc = False
                    continue

                if data_bytes and data_bytes[0].upper() == "10":
                    rx_multi_response_first = msg
                    rx_multi_response_pending = True
                    continue

                if rx_multi_response_pending and data_bytes and data_bytes[0].upper() == "21":
                    combined_bytes = rx_multi_response_first["data_bytes"][:7] + data_bytes[1:]
                    rx_msg = {
                        "timestamp": rx_multi_response_first["timestamp"],
                        "can_id": rx_multi_response_first["can_id"],
                        "direction": rx_multi_response_first["direction"],
                        "data_bytes": combined_bytes
                    }

                    if current_request:
                        status, reason = get_status(combined_bytes, current_request.get("expected_resp", ""))
                        current_request["response"] = rx_msg
                        current_request["status"] = status
                        current_request["failure_reason"] = reason
                        messages_by_tc[current_request["tc_id"]].append(current_request)

                        req_ts = current_request["timestamp"]
                        res_ts = rx_msg["timestamp"]
                        if start_ts is None or req_ts < start_ts:
                            start_ts = req_ts
                        if end_ts is None or res_ts > end_ts:
                            end_ts = res_ts

                        current_request = None

                    rx_multi_response_pending = False
                    rx_multi_response_first = None
                    continue

                if current_request and not rx_multi_response_pending:
                    status, reason = get_status(data_bytes, current_request.get("expected_resp", ""))
                    current_request["response"] = msg
                    current_request["status"] = status
                    current_request["failure_reason"] = reason
                    messages_by_tc[current_request["tc_id"]].append(current_request)

                    req_ts = current_request["timestamp"]
                    res_ts = msg["timestamp"]
                    if start_ts is None or req_ts < start_ts:
                        start_ts = req_ts
                    if end_ts is None or res_ts > end_ts:
                        end_ts = res_ts

                    current_request = None

    return messages_by_tc, start_ts or 0, end_ts or 0



def generate_html_report(messages_by_tc, output_path, asc_filename, start_ts, end_ts):
    total = len(messages_by_tc)
    passed = sum(1 for tc in messages_by_tc.values() if all(msg["status"] == "Pass" for msg in tc))
    failed = total - passed
    duration = end_ts - start_ts
    generated_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<html><head><title>UDS Diagnostic Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: Arial; margin: 20px; }}
        .pass {{ color: green; font-weight: bold; }}
        .fail {{ color: red; font-weight: bold; }}
        summary {{ font-weight: bold; cursor: pointer; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; }}
        th {{ background: #f0f0f0; }}
        #chart-container {{ width: 300px; margin: 20px auto; }}
    </style></head><body>
    <h1>UDS Diagnostic Report</h1>
    <div><strong>Generated:</strong> {generated_time}</div>
    <div><strong>CAN Log File:</strong> {asc_filename}</div>
    <div><strong>Total Test Cases:</strong> {total}</div>
    <div class="pass">Passed: {passed}</div>
    <div class="fail">Failed: {failed}</div>
    <div><strong>Test Duration:</strong> {duration:.3f} seconds</div>

    <div id="chart-container"><canvas id="passFailChart"></canvas></div>

    <script>
        const ctx = document.getElementById('passFailChart').getContext('2d');
        new Chart(ctx, {{
            type: 'pie',
            data: {{
                labels: ['Passed', 'Failed'],
                datasets: [{{
                    data: [{passed}, {failed}],
                    backgroundColor: ['#4CAF50', '#F44336']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }},
                    title: {{ display: true, text: 'Test Case Results' }}
                }}
            }}
        }});
    </script>
    <hr><br>
    """

    for tc_id, steps in messages_by_tc.items():
        status = steps[0]['status']
        status_class = 'pass' if status == 'Pass' else 'fail'
        html += f"<details><summary>{tc_id} - <span class='{status_class}'>{status}</span></summary>\n"
        html += """<table><tr><th>Step</th><th>Description</th><th>Timestamp</th><th>Type</th><th>Status</th><th>Failure Reason</th></tr>\n"""
        step_count = 1
        for msg in steps:
            html += f"<tr><td>{step_count}</td><td>{escape(msg['desc'])}</td><td>{msg['timestamp']:.6f}</td><td>Request Sent</td><td></td><td>-</td></tr>\n"
            step_count += 1
            response = msg.get("response", {})
            html += f"<tr><td>{step_count}</td><td></td><td>{response.get('timestamp', ''):.6f}</td><td>Response Received</td><td>{msg['status']}</td><td>{msg.get('failure_reason', '')}</td></tr>\n"
            step_count += 1
        html += "</table></details>\n"

    html += "</body></html>"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"✅ UDS HTML Report generated at:\n{output_path}\n")

def generte_report(asc_file_path, txt_file_path, allowed_tx_ids, allowed_rx_ids):
    global DESCRIPTION_MAP
    DESCRIPTION_MAP = load_description_map(txt_file_path)
    get_description.used_tc_ids = set()

    messages_by_tc, start_ts, end_ts = parse_asc_file(
        asc_file_path, allowed_tx_ids, allowed_rx_ids
    )

    report_path = os.path.splitext(asc_file_path)[0] + "_UDS_Report.html"
    generate_html_report(messages_by_tc, report_path, os.path.basename(asc_file_path), start_ts, end_ts)





generteself.allowed_tx_ids = [
    int(phys_cfg.get("tx_id", "0"), 16),
    int(func_cfg.get("tx_id", "0"), 16)
]

self.allowed_rx_ids = [
    int(phys_cfg.get("rx_id", "0"), 16),
    int(func_cfg.get("rx_id", "0"), 16)
]
_report(asc_file_path, txt_file_path, allowed_tx_ids, allowed_rx_ids)