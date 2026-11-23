import os
import re
import logging

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

logger = logging.getLogger(__name__)


def compile_rule(rule_text):
    if not YARA_AVAILABLE:
        return None, "yara-python is not installed"
    try:
        compiled = yara.compile(source=rule_text)
        return compiled, None
    except yara.SyntaxError as e:
        return None, f"YARA syntax error: {str(e)}"
    except Exception as e:
        return None, f"YARA compilation error: {str(e)}"


def scan_clean_directory(compiled_rule, clean_dir):
    matches = []
    if not os.path.isdir(clean_dir):
        return matches

    for root, dirs, files in os.walk(clean_dir):
        for filename in files:
            if filename == "README.md":
                continue
            filepath = os.path.join(root, filename)
            try:
                file_matches = compiled_rule.match(filepath, timeout=10)
                if file_matches:
                    matched_strings = []
                    for match in file_matches:
                        for string_match in match.strings:
                            for instance in string_match.instances:
                                matched_strings.append(string_match.identifier)
                    matches.append({
                        "file": filepath,
                        "matched_strings": list(set(matched_strings)),
                    })
            except yara.TimeoutError:
                logger.warning(f"YARA scan timed out on {filepath}")
            except Exception as e:
                logger.warning(f"Error scanning {filepath}: {e}")

    return matches


def remove_offending_strings(rule_text, offending_identifiers):
    lines = rule_text.split("\n")
    cleaned_lines = []
    removed_count = 0

    for line in lines:
        stripped = line.strip()
        should_remove = False
        for ident in offending_identifiers:
            if stripped.startswith(f"{ident} =") or stripped.startswith(f"{ident}="):
                should_remove = True
                removed_count += 1
                break
        if not should_remove:
            cleaned_lines.append(line)

    result = "\n".join(cleaned_lines)

    remaining_strings = re.findall(r"\$s\d+", result)
    if remaining_strings:
        current_threshold = re.search(r"(\d+) of \(\$s\*\)", result)
        if current_threshold:
            old_threshold = int(current_threshold.group(1))
            new_threshold = max(1, old_threshold - removed_count)
            result = result.replace(
                f"{old_threshold} of ($s*)",
                f"{new_threshold} of ($s*)"
            )
    return result


def validate(rule_text, clean_dir, max_iterations=10):
    if not YARA_AVAILABLE:
        return rule_text, "SKIPPED", 0

    if not os.path.isdir(clean_dir) or not any(
        f for f in os.listdir(clean_dir) if f != "README.md"
    ):
        return rule_text, "PASSED_NO_SAMPLES", 0

    total_false_positives = 0
    current_rule = rule_text

    for iteration in range(max_iterations):
        compiled, error = compile_rule(current_rule)
        if compiled is None:
            logger.error(f"Compilation failed on iteration {iteration}: {error}")
            return current_rule, "COMPILATION_ERROR", total_false_positives

        fp_matches = scan_clean_directory(compiled, clean_dir)

        if not fp_matches:
            return current_rule, "PASSED", total_false_positives

        total_false_positives += len(fp_matches)
        offending = set()
        for match in fp_matches:
            for ident in match.get("matched_strings", []):
                offending.add(ident)

        if not offending:
            return current_rule, "PASSED", total_false_positives

        current_rule = remove_offending_strings(current_rule, offending)
        logger.info(
            f"Iteration {iteration + 1}: removed {len(offending)} offending strings, "
            f"{total_false_positives} total false positives"
        )

    return current_rule, "PARTIAL", total_false_positives
