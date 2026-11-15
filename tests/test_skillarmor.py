"""skillarmor 扫描器测试：全部基于 fixtures 合成数据，不触碰真实用户配置。"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import skillarmor  # noqa: E402

FIX = REPO / "tests" / "fixtures"


def run_scan(root: Path) -> list[skillarmor.Finding]:
    return skillarmor.scan([root], base=root)


class TextInjectionTests(unittest.TestCase):
    def setUp(self):
        self.findings = run_scan(FIX / "skills" / "malicious")

    def test_detects_override_instruction(self):
        self.assertTrue(any(f.rule == "INJ-override" for f in self.findings))

    def test_detects_credential_exfiltration(self):
        self.assertTrue(any(f.rule == "INJ-exfiltrate" for f in self.findings))

    def test_detects_covert_behavior(self):
        self.assertTrue(any(f.rule == "INJ-covert" for f in self.findings))

    def test_detects_obfuscated_blob(self):
        self.assertTrue(any(f.rule == "OBF-blob" for f in self.findings))

    def test_high_severity_present(self):
        self.assertTrue(any(f.severity == "high" for f in self.findings))


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.findings = run_scan(FIX / "configs")

    def test_detects_bypass_permissions(self):
        self.assertTrue(any(f.rule == "PERM-bypass" for f in self.findings))

    def test_detects_wildcard_allowlist(self):
        self.assertTrue(any(f.rule == "PERM-wildcard" for f in self.findings))

    def test_detects_plaintext_api_key(self):
        self.assertTrue(any(f.rule == "CRED-openai" for f in self.findings))

    def test_mcp_description_scanned_for_injection(self):
        self.assertTrue(any(f.rule == "INJ-covert" for f in self.findings))


class HookTests(unittest.TestCase):
    def test_detects_curl_pipe_sh(self):
        findings = run_scan(FIX / "hooks")
        self.assertTrue(any(f.rule == "HOOK-remote-exec" for f in findings))


class CleanTests(unittest.TestCase):
    def test_clean_file_has_no_findings(self):
        findings = run_scan(FIX / "clean")
        self.assertEqual(findings, [])

    def test_line_numbers_are_real(self):
        findings = run_scan(FIX / "skills" / "malicious")
        for f in findings:
            self.assertGreaterEqual(f.line, 1)


class DefensiveDocsTests(unittest.TestCase):
    """官方安全文档/防御性 skill：引用语境降级、围栏内容豁免。"""

    def setUp(self):
        self.findings = run_scan(FIX / "skills" / "defensive")

    def test_quoted_override_downgraded_to_low(self):
        override = [f for f in self.findings if f.rule == "INJ-override"]
        self.assertTrue(override)
        self.assertTrue(all(f.severity != "high" for f in override))
        self.assertTrue(all(f.severity == "low" for f in override))

    def test_fenced_code_block_not_flagged_as_exfiltration(self):
        # 围栏内的示例文本不构成注入面
        self.assertTrue(all(f.rule != "INJ-exfiltrate" for f in self.findings))

    def test_document_still_flags_real_prose_findings_only(self):
        # 文档本身的防御性说明（无凭据/无真指令）不应产生 high
        self.assertFalse(any(f.severity == "high" for f in self.findings))


class CliTests(unittest.TestCase):
    def test_json_output_shape(self):
        proc = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "skillarmor.py"),
             "--root", str(FIX / "skills" / "malicious"), "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, list)
        self.assertTrue(data)
        self.assertIn("rule", data[0])

    def test_exit_code_2_on_high_findings(self):
        proc = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "skillarmor.py"),
             "--root", str(FIX / "skills" / "malicious")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)

    def test_exit_code_0_when_clean(self):
        proc = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "skillarmor.py"),
             "--root", str(FIX / "clean")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
