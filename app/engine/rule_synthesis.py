import re
from datetime import datetime, timezone


def clean_string_for_yara(s):
    cleaned = s.replace("\\", "\\\\").replace('"', '\\"')
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", cleaned)
    return cleaned.strip()


def select_rule_strings(suspicious_strings):
    high = []
    medium = []
    for entry in suspicious_strings:
        fidelity = entry.get("fidelity", "medium")
        entry_type = entry.get("type", "")
        value = entry.get("value", "").strip()
        if not value or len(value) < 4:
            continue
        if entry_type in ("url", "ip_address", "domain", "behavior_indicator"):
            high.append(entry)
        elif fidelity == "high":
            high.append(entry)
        elif fidelity == "medium":
            medium.append(entry)

    selected = high[:]
    if len(selected) < 5:
        selected += medium[: max(0, 5 - len(selected))]
    return selected


def extract_behavior_indicators(behaviors):
    high_severity = {"Code Injection", "Network Beaconing", "Privilege Escalation", "Input Capture", "Process Hollowing"}
    indicators = []
    seen = set()
    for behavior in behaviors:
        severity = behavior.get("severity", "")
        if severity not in high_severity:
            continue
        args = behavior.get("arguments", {})
        for key, val in args.items():
            if key in ("hostname", "server", "url") and val and val not in seen and len(val) > 4:
                seen.add(val)
                indicators.append({"value": val, "type": "behavior_indicator", "fidelity": "high"})
    return indicators


def synthesize(sha256, static_result, dynamic_result, match_threshold=3):
    rule_name = f"AMTS_{sha256[:16]}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    suspicious_strings = static_result.get("suspicious_strings", [])

    behaviors = dynamic_result.get("behaviors", [])
    behavior_indicators = extract_behavior_indicators(behaviors)

    existing_values = {e["value"] for e in suspicious_strings}
    for ind in behavior_indicators:
        if ind["value"] not in existing_values:
            suspicious_strings.append(ind)

    rule_strings = select_rule_strings(suspicious_strings)

    imphash = static_result.get("imphash")

    string_definitions = []
    string_names = []

    if imphash:
        hex_bytes = " ".join(imphash[i:i + 2] for i in range(0, len(imphash), 2))
        string_definitions.append(f'        $imphash = {{ {hex_bytes} }}')
        string_names.append("$imphash")

    for i, entry in enumerate(rule_strings):
        value = entry.get("value", "")
        cleaned = clean_string_for_yara(value)
        if cleaned:
            var_name = f"$s{i}"
            string_definitions.append(f'        {var_name} = "{cleaned}"')
            string_names.append(var_name)

    if not string_definitions:
        string_definitions.append('        $mz_marker = { 4D 5A }')
        string_names.append("$mz_marker")

    string_only_names = [n for n in string_names if n.startswith("$s")]
    effective_threshold = min(match_threshold, len(string_only_names))

    condition_parts = ["uint16(0) == 0x5A4D"]
    if imphash and string_only_names:
        if effective_threshold > 0:
            condition_parts.append(f"($imphash or {effective_threshold} of ($s*))")
        else:
            condition_parts.append("$imphash")
    elif imphash:
        condition_parts.append("$imphash")
    elif string_only_names and effective_threshold > 0:
        condition_parts.append(f"{effective_threshold} of ($s*)")
    elif string_only_names:
        condition_parts.append("any of ($s*)")
    else:
        condition_parts.append("$mz_marker")

    condition_str = " and ".join(condition_parts)

    sections = static_result.get("sections", [])
    packed_sections = [s["name"] for s in sections if s.get("is_packed")]
    packed_note = ", ".join(packed_sections) if packed_sections else "none"
    emulation_success = dynamic_result.get("emulation_success", False)

    high_count = sum(1 for e in suspicious_strings if e.get("fidelity") == "high" or e.get("type") in ("url", "ip_address", "domain"))
    medium_count = sum(1 for e in suspicious_strings if e.get("fidelity") == "medium")

    rule_text = f"""rule {rule_name}
{{
    meta:
        author = "AMTS-Engine"
        date = "{timestamp}"
        sha256 = "{sha256}"
        description = "Auto-generated YARA rule for sample {sha256[:16]}"
        packed_sections = "{packed_note}"
        emulation_performed = "{str(emulation_success).lower()}"
        high_fidelity_indicators = "{high_count}"
        medium_fidelity_indicators = "{medium_count}"

    strings:
{chr(10).join(string_definitions)}

    condition:
        {condition_str}
}}
"""
    return rule_name, rule_text, rule_strings
