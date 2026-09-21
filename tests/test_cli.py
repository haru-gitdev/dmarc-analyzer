import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "dmarc-analyzer.py"


VALID_XML = """<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <policy_published>
    <domain>example.com</domain><adkim>r</adkim><aspf>r</aspf><p>reject</p>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.10</source_ip><count>12</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from><envelope_from>bounce.example.com</envelope_from></identifiers>
    <auth_results>
      <spf><domain>bounce.example.com</domain><result>pass</result></spf>
      <dkim><domain>mailer.external.example</domain><selector>selector-with-a-long-name</selector><result>fail</result></dkim>
    </auth_results>
  </record>
</feedback>
"""


class DmarcAnalyzerCliTest(unittest.TestCase):
    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, arguments)],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_writes_reports_then_archives_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            reports = root / "reports"
            processed = root / "processed"
            inbox.mkdir()
            archive = inbox / "aggregate.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("aggregate.xml", VALID_XML)

            json_report = reports / "latest.json"
            html_report = reports / "latest.html"
            result = self.run_cli(
                "--dir", inbox,
                "--json-output", json_report,
                "--html-output", html_report,
                "--archive-dir", processed,
                "--no-color",
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(archive.exists())
            self.assertEqual(len(list(processed.glob("*/*.zip"))), 1)
            self.assertFalse((inbox / "aggregate.xml").exists())
            report = json.loads(json_report.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["message_count"], 12)
            self.assertEqual(report["summary"]["dmarc_failures"], 0)
            self.assertEqual(report["summary"]["error_record_groups"], 1)
            html = html_report.read_text(encoding="utf-8")
            self.assertIn("overflow-x:auto", html)
            self.assertIn("mailer.external.example", html)

    def test_parse_failure_preserves_source_and_skips_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            archive = inbox / "broken.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("broken.xml", "<feedback>")

            json_report = root / "reports" / "latest.json"
            result = self.run_cli(
                "--dir", inbox,
                "--json-output", json_report,
                "--archive-dir", root / "processed",
            )

            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertTrue(archive.exists())
            self.assertFalse(json_report.exists())
            self.assertFalse((inbox / "broken.xml").exists())


if __name__ == "__main__":
    unittest.main()
