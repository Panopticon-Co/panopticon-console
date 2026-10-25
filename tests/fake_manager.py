"""Tiny stand-in for panopticon-manager's analyst API, for local demos and
screenshots only. Serves contract-shaped data (CONTRACT.md section 7) for one
two-stage incident and accepts status changes and approve/reject decisions in
memory. Not used by the unit tests and not a substitute for Manager.

    python tests/fake_manager.py --port 8799 --token demo-token
    PANOPTICON_MANAGER_TOKEN=demo-token python app.py --manager-url http://127.0.0.1:8799
"""
from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STAGE_ALERT = {
    "alert_id": "ALT-3f9a1c", "rule_id": "DET-PROC-011", "detection_source": "rule",
    "title": "High-Entropy Obfuscated Script Execution", "description": "PowerShell launched with an encoded command.",
    "level": 11, "severity": "high", "confidence": 0.8, "host_id": "WS-ACCT-07", "timestamp": "2026-10-25T08:00:04Z",
    "event_id": "evt-101", "mitre_tactic": "Execution", "mitre_technique": "T1059.001", "incident_id": None,
    "evidence": {"process.name": "powershell.exe", "process.pid": 4242,
                 "process.command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
                 "process.parent.name": "cmd.exe",
                 "matched_conditions": ["process.name equals powershell.exe", "process.command_line contains -enc"]},
    "active_response": {"action": "TERMINATE_PROCESS", "host_id": "WS-ACCT-07", "target_pid": 4242,
                        "target_guid": None, "target_start_time_ticks": "133740000041234567", "target_file": None,
                        "reason": "Obfuscated PowerShell spawned from an Office document"},
    "tags": ["process"], "compliance": [],
}
BEACON_ALERT = {
    "alert_id": "ALT-BCN-77e2", "rule_id": "BEH-BEACON-001", "detection_source": "behavioral",
    "title": "Periodic outbound connection (beacon-like)", "level": 8, "severity": "medium", "confidence": 0.5,
    "host_id": "WS-ACCT-07", "timestamp": "2026-10-25T08:03:10Z", "event_id": "evt-140",
    "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001", "incident_id": None,
    "evidence": {"process.name": "powershell.exe", "network.remote_ip": "203.0.113.50", "network.remote_port": 443,
                 "matched_conditions": ["12 connections, jitter 4%"]},
    "active_response": {"action": "COLLECT_NETWORK_CONNECTIONS", "host_id": "WS-ACCT-07", "target_pid": 4242,
                        "target_guid": None, "target_start_time_ticks": "133740000041234567", "target_file": None,
                        "reason": "Snapshot connections of the beaconing process"},
    "tags": ["network"], "compliance": [],
}
NET_ALERT = dict(STAGE_ALERT, alert_id="ALT-8c21de", rule_id="DET-NET-004", title="PowerShell connection to a public address",
                 description="", level=10, severity="high", confidence=0.6, timestamp="2026-10-25T08:01:30Z",
                 event_id="evt-122", mitre_tactic="Command and Control", mitre_technique="T1071.001",
                 evidence={"process.name": "powershell.exe", "network.remote_ip": "203.0.113.50",
                           "matched_conditions": ["process.name equals powershell.exe", "destination scope is public"]},
                 active_response=None, tags=["network"])
EVIDENCE = {
    "incident_id": "INC-WS-ACCT-07-4f1b", "revision": 2,
    "attack_chain": "DET-PROC-011 (Execution) -> DET-NET-004 (Command and Control)", "stage_count": 2,
    "stages": [
        {"time": "2026-10-25T08:00:04+00:00", "rule_id": "DET-PROC-011", "rule_name": "High-Entropy Obfuscated Script Execution",
         "tactic": "Execution", "technique": "T1059.001", "process": "powershell.exe", "pid": 4242, "event_id": "evt-101", "alert_id": "ALT-3f9a1c"},
        {"time": "2026-10-25T08:01:30+00:00", "rule_id": "DET-NET-004", "rule_name": "PowerShell connection to a public address",
         "tactic": "Command and Control", "technique": "T1071.001", "process": "powershell.exe", "pid": 4242, "event_id": "evt-122", "alert_id": "ALT-8c21de"},
        {"time": "2026-10-25T08:02:30+00:00", "rule_id": "DET-NET-004", "rule_name": "PowerShell connection to a public address",
         "tactic": "Command and Control", "technique": "T1071.001", "process": "powershell.exe", "pid": 4242, "event_id": "evt-131", "alert_id": None},
    ],
    "tactics_covered": ["Execution", "Command and Control"], "root_cause_process": "winword.exe", "root_pid": 3120,
    "root_inferred": False, "process_lineage": "explorer.exe -> winword.exe -> cmd.exe -> powershell.exe",
    "provenance_origin": "winword.exe", "processes_in_scope": 3,
    "causal_path": [
        "2026-10-25T07:59:58+00:00 winword.exe[3120] -[spawned]-> cmd.exe[3988]",
        "2026-10-25T08:00:04+00:00 cmd.exe[3988] -[spawned]-> powershell.exe[4242]",
        "2026-10-25T08:01:30+00:00 powershell.exe[4242] -[connected_to]-> 203.0.113.50:443",
    ],
    "incident_score": 7.35,
    "score_breakdown": {"stage_severity": {"weight": 4.4, "max_stage_level": 11},
                        "tactic_breadth": {"weight": 1.5, "tactics": 2},
                        "context": {"weight": 1.45, "factors": {"initial_access_vector": 0.6, "external_network": 0.5, "obfuscated_command": 0.35}},
                        "total": 7.35},
    "why": ["highest stage level 11/16", "2 ATT&CK tactic(s): Execution, Command and Control",
            "rooted at an Office application (common initial-access vector)", "connected to a public address",
            "obfuscated command line in scope"],
    "updates_since_last_alert": 1,
}
INCIDENT_ALERT = {
    "alert_id": "INC-WS-ACCT-07-4f1b-R2", "rule_id": "PROV-CAMPAIGN", "detection_source": "correlation",
    "title": "[INCIDENT] 2-tactic attack chain rooted at winword.exe", "level": 13, "severity": "critical",
    "confidence": 0.6, "host_id": "WS-ACCT-07", "timestamp": "2026-10-25T08:01:30Z", "event_id": "evt-122",
    "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001", "incident_id": "INC-WS-ACCT-07-4f1b",
    "evidence": EVIDENCE,
    "active_response": {"action": "TERMINATE_PROCESS", "host_id": "WS-ACCT-07", "target_pid": 4242, "target_guid": None,
                        "target_start_time_ticks": "133740000041234567", "target_file": None,
                        "reason": "Terminal-tactic stage of a multi-stage incident"},
    "tags": ["correlation"], "compliance": [],
}


def row(alert):
    return {"alert_id": alert["alert_id"], "rule_id": alert["rule_id"], "level": alert["level"], "severity": alert["severity"],
            "host_id": alert["host_id"], "agent_id": "agent-ws-acct-07", "event_id": alert["event_id"],
            "alert_timestamp": alert["timestamp"], "created_at": alert["timestamp"], "mitre_tactic": alert["mitre_tactic"],
            "mitre_technique": alert["mitre_technique"], "detection_source": alert["detection_source"],
            "incident_id": alert.get("incident_id"), "alert": alert}


ALERT_ROWS = [row(a) for a in (STAGE_ALERT, NET_ALERT, BEACON_ALERT, INCIDENT_ALERT)]
STATE = {
    "incident_status": "open",
    "incident_audit": [{"audit_id": "ia-1", "incident_id": "INC-WS-ACCT-07-4f1b", "event": "opened", "actor": "system:detection",
                        "detail": "revision 1", "occurred_at": "2026-10-25T08:01:30Z"},
                       {"audit_id": "ia-2", "incident_id": "INC-WS-ACCT-07-4f1b", "event": "revised", "actor": "system:detection",
                        "detail": "revision 2: tactic added", "occurred_at": "2026-10-25T08:01:30Z"}],
    "actions": [
        {"response_id": "ra-001", "alert_id": "ALT-3f9a1c", "action": "KILL_PROCESS", "tier": "ANALYST_APPROVAL", "lifecycle_state": "PENDING",
         "target": {"host_id": "WS-ACCT-07", "target_pid": 4242}, "command_id": None, "created_at": "2026-10-25T08:00:05Z",
         "authorized_at": None, "authorized_by": None, "decided_reason": "direct mapping TERMINATE_PROCESS -> KILL_PROCESS", "audit": []},
        {"response_id": "ra-002", "alert_id": "ALT-BCN-77e2", "action": "COLLECT_NETWORK_CONNECTIONS", "tier": "AUTO_SAFE", "lifecycle_state": "AUTHORIZED",
         "target": {"host_id": "WS-ACCT-07", "target_pid": 4242}, "command_id": "resp-ra-002", "command_state": "SUCCEEDED",
         "created_at": "2026-10-25T08:03:11Z", "authorized_at": "2026-10-25T08:03:11Z", "authorized_by": "system:response-engine",
         "decided_reason": "auto-safe read-only collection",
         "audit": [{"audit_id": "ca-1", "command_id": "resp-ra-002", "event": "created", "actor": "system:response-engine", "detail": None, "occurred_at": "2026-10-25T08:03:11Z"},
                   {"audit_id": "ca-2", "command_id": "resp-ra-002", "event": "delivered", "actor": "agent:agent-ws-acct-07", "detail": None, "occurred_at": "2026-10-25T08:03:14Z"},
                   {"audit_id": "ca-3", "command_id": "resp-ra-002", "event": "result_received", "actor": "agent:agent-ws-acct-07", "detail": "succeeded", "occurred_at": "2026-10-25T08:03:15Z"}]},
        {"response_id": "ra-003", "alert_id": "ALT-BCN-77e2", "action": "ISOLATE_HOST", "tier": "ANALYST_APPROVAL", "lifecycle_state": "REJECTED",
         "target": {"host_id": "WS-ACCT-07"}, "command_id": None, "created_at": "2026-10-25T08:03:11Z", "authorized_at": None,
         "authorized_by": None, "decided_reason": "disruptive action from a behavioral alert is record-only", "audit": []},
    ],
}


def summary():
    return {"incident_id": "INC-WS-ACCT-07-4f1b", "host_id": "WS-ACCT-07", "status": STATE["incident_status"], "severity": "critical",
            "level": 13, "score": 7.35, "confidence": 0.6, "tactics": ["Execution", "Command and Control"], "stage_count": 2,
            "root_process": "winword.exe", "revision": 2, "first_seen": "2026-10-25T08:00:04Z", "last_seen": "2026-10-25T08:02:30Z",
            "alert_count": 3}


def make_handler(token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _reply(self, status, obj):
            body = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self):
            if self.headers.get("Authorization") == f"Bearer {token}":
                return True
            self._reply(401, {"detail": "analyst authentication required"})
            return False

        def do_GET(self):  # noqa: N802
            if not self._authorized():
                return
            path = self.path.split("?", 1)[0]
            if path == "/api/v1/alerts":
                self._reply(200, {"alerts": ALERT_ROWS, "next_before": None})
            elif path == "/api/v1/incidents":
                self._reply(200, {"incidents": [summary()]})
            elif path == "/api/v1/incidents/INC-WS-ACCT-07-4f1b":
                self._reply(200, {"incident": dict(summary(), evidence=EVIDENCE),
                                  "alerts": [row(STAGE_ALERT), row(NET_ALERT), row(INCIDENT_ALERT)],
                                  "response_actions": [a for a in STATE["actions"] if a["alert_id"] in ("ALT-3f9a1c", "INC-WS-ACCT-07-4f1b-R2")],
                                  "audit": STATE["incident_audit"]})
            elif path == "/api/v1/response-actions":
                self._reply(200, {"response_actions": STATE["actions"]})
            elif path == "/api/v1/status":
                pending = sum(1 for a in STATE["actions"] if a["lifecycle_state"] == "PENDING")
                self._reply(200, {"events": {"pending": 2, "claimed": 1, "done": 1874, "failed": 0}, "alerts": len(ALERT_ROWS),
                                  "incidents_open": 0 if STATE["incident_status"] in ("resolved", "false_positive") else 1,
                                  "response_actions": {"PENDING": pending, "AUTHORIZED": 1, "REJECTED": 1},
                                  "agents_enrolled": 1, "last_event_at": "2026-10-25T08:03:15Z"})
            else:
                self._reply(404, {"detail": "not found"})

        def do_POST(self):  # noqa: N802
            if not self._authorized():
                return
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            if self.path == "/api/v1/incidents/INC-WS-ACCT-07-4f1b/status":
                old, STATE["incident_status"] = STATE["incident_status"], body["status"]
                STATE["incident_audit"].append({"audit_id": f"ia-{len(STATE['incident_audit']) + 1}", "event": "status_changed",
                                                "actor": "analyst:demo", "from_status": old, "to_status": body["status"],
                                                "note": body.get("note"), "occurred_at": "2026-10-25T08:10:00Z"})
                self._reply(200, {"incident_id": "INC-WS-ACCT-07-4f1b", "status": body["status"]})
                return
            match = re.fullmatch(r"/api/v1/response-actions/([^/]+)/(authorize|reject)", self.path)
            action = next((a for a in STATE["actions"] if match and a["response_id"] == match.group(1)), None)
            if action is None or action["lifecycle_state"] != "PENDING":
                self._reply(404, {"detail": "no pending response action"})
                return
            if match.group(2) == "authorize":
                action.update(lifecycle_state="AUTHORIZED", command_id="resp-" + action["response_id"], command_state="DISPATCHED",
                              authorized_by="analyst:demo", authorized_at="2026-10-25T08:11:00Z")
                action["audit"] = [{"audit_id": "ca-x", "command_id": action["command_id"], "event": "created", "actor": "analyst:demo",
                                    "detail": None, "occurred_at": "2026-10-25T08:11:00Z"}]
            else:
                action.update(lifecycle_state="REJECTED", decided_reason=body.get("reason"), authorized_by="analyst:demo")
            self._reply(200, {"response_id": action["response_id"], "lifecycle_state": action["lifecycle_state"]})

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8799)
    parser.add_argument("--token", default="demo-token")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(args.token))
    print(f"[*] fake manager on http://127.0.0.1:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
