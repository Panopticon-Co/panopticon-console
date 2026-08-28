"""Unit tests for app.read_alerts - NDJSON parsing and its failure modes.

These are pure-function tests: no socket, no threads, deterministic.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import DISPLAY_FIELDS, read_alerts  # noqa: E402

# A realistic DET-PROC-011 alert, matching panopticon-detection-engine's
# src/alerting/alert.py::Alert.to_dict() output shape.
SAMPLE_ALERT = {
    "alert_id": "ALT-DEADBEEF",
    "rule_id": "DET-PROC-011",
    "title": "High-Entropy Obfuscated Script Execution (Zero-Day Anomaly Detection)",
    "description": "Detects command-line executions exhibiting abnormal Shannon Entropy.",
    "level": 11,
    "severity": "high",
    "confidence": 0.9,
    "host_id": "a0ee8126-92a5-4ef9-b2ce-17c5d93e82c2",
    "timestamp": "2026-08-27T18:20:40.645Z",
    "event_id": "evt_89601558a7b0078493a86abad642e261",
    "evidence": {
        "process.name": "powershell.exe",
        "process.command_line": 'powershell.exe -NoProfile -EncodedCommand VwByAA==',
        "process.entropy": 4.66,
        "process.pid": 35804,
        "process.user": "SHREYAS\\Acer",
    },
    "active_response": None,
    "mitre_tactic": "Defense Evasion",
    "mitre_technique": "T1027",
    "compliance": [],
    "tags": ["attack.defense_evasion", "entropy_anomaly"],
}


def _line(obj) -> str:
    return json.dumps(obj) + "\n"


class ReadAlertsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self._tmp = Path(tmp.name)
        self.alerts_file = self._tmp / "alerts.ndjson"

    # -- missing / empty ----------------------------------------------------
    def test_missing_file_returns_empty_list(self):
        self.assertEqual(read_alerts(self._tmp / "does-not-exist.ndjson"), [])

    def test_directory_path_returns_empty_list(self):
        self.assertEqual(read_alerts(self._tmp), [])

    def test_empty_file_returns_empty_list(self):
        self.alerts_file.write_text("", encoding="utf-8")
        self.assertEqual(read_alerts(self.alerts_file), [])

    def test_whitespace_only_file_returns_empty_list(self):
        self.alerts_file.write_text("\n   \n\t\n", encoding="utf-8")
        self.assertEqual(read_alerts(self.alerts_file), [])

    # -- happy path -------------------------------------------------------
    def test_single_alert_parsed(self):
        self.alerts_file.write_text(_line(SAMPLE_ALERT), encoding="utf-8")
        got = read_alerts(self.alerts_file)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["rule_id"], "DET-PROC-011")

    def test_multiple_alerts_preserve_file_order(self):
        a = dict(SAMPLE_ALERT, alert_id="ALT-1", rule_id="DET-PROC-011")
        b = dict(SAMPLE_ALERT, alert_id="ALT-2", rule_id="DET-PROC-099")
        self.alerts_file.write_text(_line(a) + _line(b), encoding="utf-8")
        got = read_alerts(self.alerts_file)
        self.assertEqual([x["alert_id"] for x in got], ["ALT-1", "ALT-2"])

    def test_all_display_fields_present_in_sample(self):
        self.alerts_file.write_text(_line(SAMPLE_ALERT), encoding="utf-8")
        got = read_alerts(self.alerts_file)[0]
        for field in DISPLAY_FIELDS:
            self.assertIn(field, got, f"display field {field!r} missing from alert contract")

    # -- malformed input ------------------------------------------------------
    def test_malformed_middle_line_is_skipped_others_kept(self):
        self.alerts_file.write_text(
            _line(dict(SAMPLE_ALERT, alert_id="ALT-1"))
            + "{ this is not json ]\n"
            + _line(dict(SAMPLE_ALERT, alert_id="ALT-2")),
            encoding="utf-8",
        )
        got = read_alerts(self.alerts_file)
        self.assertEqual([x["alert_id"] for x in got], ["ALT-1", "ALT-2"])

    def test_truncated_final_line_is_skipped(self):
        # engine half-flushed the last record while the console polled
        self.alerts_file.write_text(
            _line(dict(SAMPLE_ALERT, alert_id="ALT-1")) + '{"alert_id": "ALT-2", "rule_i',
            encoding="utf-8",
        )
        got = read_alerts(self.alerts_file)
        self.assertEqual([x["alert_id"] for x in got], ["ALT-1"])

    def test_non_object_json_lines_are_skipped(self):
        self.alerts_file.write_text(
            "[1, 2, 3]\n" + '"just a string"\n' + _line(SAMPLE_ALERT),
            encoding="utf-8",
        )
        got = read_alerts(self.alerts_file)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["rule_id"], "DET-PROC-011")

    def test_blank_lines_between_records_are_ignored(self):
        self.alerts_file.write_text(
            "\n" + _line(dict(SAMPLE_ALERT, alert_id="ALT-1")) + "\n\n"
            + _line(dict(SAMPLE_ALERT, alert_id="ALT-2")) + "\n",
            encoding="utf-8",
        )
        got = read_alerts(self.alerts_file)
        self.assertEqual([x["alert_id"] for x in got], ["ALT-1", "ALT-2"])

    # -- V2 incremental / live consumption --------------------------------
    def test_reader_sees_new_alerts_appended_during_a_live_run(self):
        # detection-engine V2 IncrementalAlertWriter appends one line per alert
        # as it is generated. Each poll must observe the file as grown so far,
        # including while the engine is mid-write on the newest record.
        with open(self.alerts_file, "a", encoding="utf-8") as fh:
            fh.write(_line(dict(SAMPLE_ALERT, alert_id="ALT-1")))
            fh.flush()
        self.assertEqual([x["alert_id"] for x in read_alerts(self.alerts_file)], ["ALT-1"])

        with open(self.alerts_file, "a", encoding="utf-8") as fh:
            fh.write(_line(dict(SAMPLE_ALERT, alert_id="ALT-2")))
            fh.write('{"alert_id": "ALT-3", "rule_i')  # torn final record
            fh.flush()
        self.assertEqual(
            [x["alert_id"] for x in read_alerts(self.alerts_file)], ["ALT-1", "ALT-2"]
        )

        with open(self.alerts_file, "a", encoding="utf-8") as fh:
            fh.write('d": "DET-PROC-011", "evidence": {}}\n')
        self.assertEqual(
            [x["alert_id"] for x in read_alerts(self.alerts_file)],
            ["ALT-1", "ALT-2", "ALT-3"],
        )

    def test_reader_passes_duplicate_lines_through_unchanged(self):
        # The API contract is "pass every line through"; de-duplication by
        # alert_id is a client concern (static/app.js::dedupe). If the engine
        # ever re-appends a delivered alert, the reader still returns both lines
        # and the browser collapses them.
        dup = _line(dict(SAMPLE_ALERT, alert_id="ALT-DUP"))
        self.alerts_file.write_text(dup + dup, encoding="utf-8")
        got = read_alerts(self.alerts_file)
        self.assertEqual([x["alert_id"] for x in got], ["ALT-DUP", "ALT-DUP"])


if __name__ == "__main__":
    unittest.main()
