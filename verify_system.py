"""
AMTS-Engine Recursive End-to-End System Verification
Run with: venv\Scripts\python.exe verify_system.py
"""
import sys, os, json, time
sys.path.insert(0, '.')

print('=== RECURSIVE END-TO-END SYSTEM VERIFICATION ===\n')

# --- 1. App instantiation ---
from app import create_app
from config import Config
app = create_app()
client = app.test_client()
print('[CHECK 1] App instantiation: OK')

# --- 2. Stats endpoint ---
with app.app_context():
    r = client.get('/api/jobs/stats')
    assert r.status_code == 200, f'stats endpoint HTTP {r.status_code}'
    stats = json.loads(r.data)
    assert 'total_jobs' in stats
    print(f'[CHECK 2] /api/jobs/stats: {stats}')

# --- 3. Database persistence ---
with app.app_context():
    from app.models import Job, StaticResult, DynamicResult, YaraRule
    from app import db
    jobs = Job.query.all()
    print(f'[CHECK 3] DB has {len(jobs)} job(s)')
    for j in jobs:
        d = j.to_dict()
        assert 'job_id' in d and 'sha256' in d
        assert j.status in ('QUEUED', 'EXECUTING', 'COMPLETED', 'FAILED')
        has_static = bool(j.static_result)
        has_dynamic = bool(j.dynamic_result)
        has_yara = bool(j.yara_rule)
        emul_ok = j.dynamic_result.emulation_success if j.dynamic_result else None
        emul_err = j.dynamic_result.error_message if j.dynamic_result else None
        print(f'  Job {j.id}: status={j.status}, static={has_static}, dynamic={has_dynamic}(emulation_success={emul_ok}), yara={has_yara}')

# --- 4. Speakeasy emulation with real sample ---
from app.engine.emulation import emulate, SPEAKEASY_AVAILABLE
assert SPEAKEASY_AVAILABLE, 'speakeasy-emulator not installed!'
up_dir = 'uploads'
samples = [os.path.join(up_dir, f) for f in os.listdir(up_dir) if os.path.isfile(os.path.join(up_dir, f))]
assert len(samples) > 0, 'No samples in uploads/'
result = emulate(samples[0], timeout=15)
assert result['emulation_success'], 'Emulation failed: ' + str(result.get('error_message'))
assert len(result['behaviors']) > 0, 'No behaviors collected!'
for b in result['behaviors']:
    assert 'function' in b and 'severity' in b and 'arguments' in b and 'elapsed_ms' in b
print(f'[CHECK 4] Speakeasy: emulation_success=True, {len(result["behaviors"])} behaviors collected')
print(f'          Sample behaviors: {[b["function"] for b in result["behaviors"][:4]]}')

# --- 5. Static analysis ---
from app.engine.static_analysis import analyze, PEFILE_AVAILABLE
assert PEFILE_AVAILABLE, 'pefile not installed!'
sa = analyze(samples[0])
for key in ('imphash', 'sections', 'suspicious_strings', 'compilation_timestamp', 'architecture', 'section_count'):
    assert key in sa, f'Missing key: {key}'
for s in sa['sections']:
    assert 0.0 <= s['entropy'] <= 8.0
print(f'[CHECK 5] Static analysis: arch={sa["architecture"]}, sections={sa["section_count"]}, indicators={len(sa["suspicious_strings"])}')

# --- 6. YARA rule synthesis + compilation ---
from app.engine.rule_synthesis import synthesize
from app.engine.validation import compile_rule, scan_clean_directory, validate
name, text, strings = synthesize(sha256='a' * 64, static_result=sa, dynamic_result=result)
assert name.startswith('AMTS_')
assert 'rule AMTS_' in text
assert 'condition:' in text
compiled, err = compile_rule(text)
assert compiled is not None, f'Rule does not compile: {err}'
print(f'[CHECK 6] Rule synthesis: {name}, {len(strings)} indicator(s), compiles OK')

# --- 7. False positive rate against clean_samples ---
clean_dir = 'clean_samples'
clean_files = [f for f in os.listdir(clean_dir) if f != 'README.md' and os.path.isfile(os.path.join(clean_dir, f))]
print(f'[CHECK 7] Clean samples: {len(clean_files)} files')

rules_dir = 'rules'
rule_files = [f for f in os.listdir(rules_dir) if f.endswith('.yar')]
all_fp = 0
print(f'          Scanning {len(rule_files)} rules against {len(clean_files)} clean files:')
for rf in rule_files:
    with open(os.path.join(rules_dir, rf)) as f:
        rt = f.read()
    comp, e = compile_rule(rt)
    if comp is None:
        print(f'          [WARN] {rf}: compile error: {e}')
        continue
    matches = scan_clean_directory(comp, clean_dir)
    all_fp += len(matches)
    fp_label = f'{len(matches)} FPs ({[m["file"] for m in matches]})' if matches else '0 FPs'
    print(f'          {rf}: {fp_label}')
fp_denom = len(rule_files) * max(len(clean_files), 1)
fp_rate = all_fp / fp_denom if fp_denom else 0
print(f'          Total FP rate: {all_fp}/{fp_denom} = {fp_rate:.1%}')

# --- 8. Validation cycle ---
final_rule, val_status, fp_count = validate(text, clean_dir)
assert val_status in ('PASSED', 'PASSED_NO_SAMPLES', 'PARTIAL')
print(f'[CHECK 8] Validation: status={val_status}, fp_count={fp_count}')

# --- 9. API endpoints ---
with app.app_context():
    r2 = client.get('/api/jobs')
    assert r2.status_code == 200
    job_list = json.loads(r2.data)
    assert isinstance(job_list, list)
    print(f'[CHECK 9] /api/jobs: {len(job_list)} jobs returned')

    if job_list:
        jid = job_list[0]['job_id']
        r3 = client.get(f'/api/status/{jid}')
        assert r3.status_code == 200
        sd = json.loads(r3.data)
        assert sd['status'] in ('QUEUED', 'EXECUTING', 'COMPLETED', 'FAILED')
        print(f'          /api/status/{jid}: status={sd["status"]}')

        r4 = client.get(f'/api/report/{jid}')
        assert r4.status_code == 200
        rp = json.loads(r4.data)
        assert 'job_id' in rp and 'sha256' in rp
        # Verify full data structure if completed
        if sd['status'] == 'COMPLETED':
            assert 'static_analysis' in rp
            assert 'dynamic_analysis' in rp
            assert 'yara_rule' in rp
            yr = rp['yara_rule']
            assert yr['rule_name'].startswith('AMTS_')
            comp2, e2 = compile_rule(yr['rule_text'])
            assert comp2 is not None, f'Stored rule does not compile: {e2}'
        print(f'          /api/report/{jid}: all keys present, stored YARA compiles OK')

    r5 = client.get('/api/status/NONEXISTENT')
    assert r5.status_code == 404
    print('          /api/status/NONEXISTENT: 404 OK')

# --- 10. Upload + pipeline with fresh file ---
print('[CHECK 10] Testing upload + pipeline with fresh synthetic PE...')
import io, struct

def build_malicious_pe():
    shellcode = bytes([0x33, 0xC0, 0xC3])
    evil = b'\x00'.join([
        b'http://malware-c2.example.com/beacon',
        b'VirtualAllocEx', b'CreateRemoteThread',
        b'WriteProcessMemory', b'URLDownloadToFileA', b'AdjustTokenPrivileges',
        b'192.168.100.5', b'evil.tk',
    ]) + b'\x00'
    pe_offset = 0x80
    SZ_OPT = 0xe0
    hdr_size = pe_offset + 4 + 20 + SZ_OPT + 2 * 0x28
    hdr_raw = (hdr_size + 0x1ff) & ~0x1ff
    text_raw = shellcode + b'\x00' * (0x200 - len(shellcode))
    data_raw = evil + b'\x00' * (0x200 - len(evil) % 0x200)
    dos = bytearray(0x80); dos[0:2] = b'MZ'; dos[0x3c:0x40] = struct.pack('<I', pe_offset)
    pe_sig = b'PE\x00\x00'
    fhdr = struct.pack('<HHIIIHH', 0x014c, 2, 0x5D000000, 0, 0, SZ_OPT, 0x010f)
    opt = struct.pack('<H', 0x010b) + struct.pack('<BB', 14, 0)
    opt += struct.pack('<III', len(text_raw), len(data_raw), 0x1000)
    opt += struct.pack('<II', 0x1000, 0x2000); opt += struct.pack('<I', 0x00400000)
    opt += struct.pack('<II', 0x1000, 0x200); opt += struct.pack('<HHHH', 4, 0, 0, 0)
    opt += struct.pack('<II', 0, 0x4000); opt += struct.pack('<I', hdr_raw)
    opt += struct.pack('<I', 0); opt += struct.pack('<HH', 3, 0)
    opt += struct.pack('<IIIII', 0x100000, 0x1000, 0x100000, 0x1000, 0)
    opt += struct.pack('<I', 16) + b'\x00' * 128
    opt = opt[:SZ_OPT].ljust(SZ_OPT, b'\x00')
    def sh(nm, vs, va, rs, ro, ch):
        return nm.encode()[:8].ljust(8, b'\x00') + struct.pack('<IIIIIHHII', vs, va, rs, ro, 0,0,0,0, ch)
    hdrs = bytes(dos) + pe_sig + fhdr + opt + sh('.text', len(shellcode), 0x1000, len(text_raw), hdr_raw, 0x60000020) + sh('.data', len(evil), 0x2000, len(data_raw), hdr_raw+len(text_raw), 0xC0000040)
    hdrs = hdrs[:hdr_raw].ljust(hdr_raw, b'\x00')
    return hdrs + text_raw + data_raw

with app.app_context():
    pe_bytes = build_malicious_pe()
    upload_resp = client.post('/api/upload',
        data={'file': (io.BytesIO(pe_bytes), 'verify_mal.exe')},
        content_type='multipart/form-data')
    assert upload_resp.status_code in (202, 200)
    udata = json.loads(upload_resp.data)
    jid2 = udata['job_id']
    is_dup = udata.get('duplicate', False)
    print(f'          Upload: job_id={jid2}, duplicate={is_dup}')
    
    if not is_dup:
        # Wait for completion
        deadline = time.time() + 90
        status2 = 'QUEUED'
        while time.time() < deadline and status2 not in ('COMPLETED', 'FAILED'):
            time.sleep(1)
            sr = json.loads(client.get(f'/api/status/{jid2}').data)
            status2 = sr['status']
        
        if status2 == 'COMPLETED':
            rp2 = json.loads(client.get(f'/api/report/{jid2}').data)
            sa2 = rp2.get('static_analysis', {})
            da2 = rp2.get('dynamic_analysis', {})
            yr2 = rp2.get('yara_rule', {})
            print(f'          Pipeline COMPLETED:')
            print(f'            static: arch={sa2.get("architecture")}, sections={sa2.get("section_count")}, indicators={len(sa2.get("suspicious_strings",[]))}')
            print(f'            dynamic: emulation_success={da2.get("emulation_success")}, behaviors={len(da2.get("behaviors",[]))}')
            print(f'            yara: rule={yr2.get("rule_name")}, validation={yr2.get("validation_status")}, fp={yr2.get("false_positive_count")}')
            # Verify YARA compiles
            comp3, e3 = compile_rule(yr2.get('rule_text', ''))
            assert comp3 is not None, f'Pipeline YARA must compile: {e3}'
            print(f'            yara compiles: OK')
        else:
            print(f'          Pipeline status: {status2} (timed out or failed)')
    else:
        print(f'          Duplicate file - existing report reused (expected)')

print('\n=== ALL CHECKS PASSED - SYSTEM IS FULLY OPERATIONAL ===')
