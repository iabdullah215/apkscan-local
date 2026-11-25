import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "data" / "synth"), str(ROOT / "data")]

from apkscan.chunking import chunk_file, normalize_xml
from apkscan.schema import parse_output, make_finding, class_ids
from apkscan.report import dedupe
from eval.metrics import score


def test_classes_fixed():
    assert class_ids() == ["exported_component", "insecure_webview", "hardcoded_secret", "weak_crypto",
                           "insecure_network", "insecure_storage", "provider_sqli", "intent_redirection"]


def test_parse_strict_and_recovered():
    f = make_finding("weak_crypto", "medium", "a.java", [3, 3], "e", "w", "f")
    assert parse_output(json.dumps([f])).strict_json
    r = parse_output("```json\n" + json.dumps([f]) + "\n```")
    assert r.parsed and not r.strict_json and len(r.findings) == 1
    assert parse_output("[]").strict_json and parse_output("[]").findings == []
    assert not parse_output("no findings").parsed


def test_schema_errors_flag_bad_class():
    r = parse_output('[{"vuln_class": "xss", "line_range": [1, 2]}]')
    assert r.parsed and not r.schema_valid and r.findings == []


def test_chunk_keeps_original_line_numbers():
    src = "package a;\n\nimport x.y;\nimport z.w;\n\npublic class A {\n    void f() {\n        g();\n    }\n}\n"
    (c,) = chunk_file("a/A.java", src)
    assert "import" not in c.body
    assert "   8|         g();" in c.body
    assert c.start == 1 and c.end == 10


def test_long_file_splits_without_losing_lines():
    body = "\n".join(f"    void m{i}() {{\n        call{i}();\n    }}\n" for i in range(200))
    src = "package a;\npublic class B {\n" + body + "}\n"
    chunks = chunk_file("a/B.java", src)
    assert len(chunks) > 1
    seen = set()
    for c in chunks:
        for l in c.body.splitlines():
            seen.add(int(l.split("|")[0]))
    nonblank = {i + 1 for i, l in enumerate(src.splitlines()) if l.strip()}
    assert nonblank <= seen


def test_normalize_manifest_one_element_per_line():
    xml = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="p">'
           '<application><activity\n android:name=".A"\n android:exported="true"/></application></manifest>')
    out = normalize_xml(xml).splitlines()
    assert any('<activity android:name=".A" android:exported="true"/>' in l for l in out)


def test_metrics_overlap_dup_ignore():
    gold = [{"file": "f", "vuln_class": "weak_crypto", "line_range": [10, 12]}]
    ignore = [{"file": "f", "line_range": [40, 45]}]
    preds = [{"file": "f", "vuln_class": "weak_crypto", "line_range": [13, 13]},   # tp (tolerance)
             {"file": "f", "vuln_class": "weak_crypto", "line_range": [11, 11]},   # dup
             {"file": "f", "vuln_class": "weak_crypto", "line_range": [42, 42]},   # ignored
             {"file": "f", "vuln_class": "insecure_storage", "line_range": [80, 80]}]  # fp
    s = score(gold, ignore, preds, class_ids())
    assert s["overall"]["tp"] == 1 and s["overall"]["fp"] == 1 and s["overall"]["fn"] == 0


def test_dedupe_report():
    a = make_finding("weak_crypto", "low", "f", [1, 3], "e", "w", "x")
    b = make_finding("weak_crypto", "high", "f", [2, 2], "e", "w", "x")
    assert len(dedupe([a, b])) == 1


def test_synthetic_labels_pass_rules_and_are_deterministic():
    import generator
    from builder import check_sample
    s1 = generator.generate(7, 60, 10, 6)
    s2 = generator.generate(7, 60, 10, 6)
    assert [x.text for x in s1] == [x.text for x in s2]
    for s in s1:
        assert check_sample(s.text, s.findings) == [], s.file


def test_no_test_app_text_in_training_data():
    train = (ROOT / "data" / "processed" / "train.jsonl").read_text()
    for needle in ["oversecured", "insecurebankv2", "This is the super secret key", "49u5gh249gh24985ghf429gh4ch8f23f"]:
        assert needle not in train, needle


def test_parse_byclass_form():
    obj = {"weak_crypto": [{"cwe": "CWE-327", "masvs": "MASVS-CRYPTO-1", "severity": "medium", "file": "a", "line_range": [2, 2],
                            "evidence": "e", "why_exploitable": "w", "fix": "f"}], "insecure_network": []}
    r = parse_output(json.dumps(obj))
    assert r.parsed and len(r.findings) == 1 and r.findings[0]["vuln_class"] == "weak_crypto"
