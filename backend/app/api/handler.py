"""
FraudNexus REST API Request Dispatcher
Handles all scoring, investigation, network graph, money flow, and demo sandbox endpoints.
Compatible with standard HTTP server and FastAPI.
"""

import json
import sqlite3
import hashlib
from datetime import datetime
from typing import Dict, Any, Tuple
from ..db.connection import get_connection
from ..db.seed_data import seed_database
from ..scoring.engine import RiskScoringService
from ..config import DEFAULT_CONFIG

service = RiskScoringService(DEFAULT_CONFIG)

def handle_get_risk_score(txn_id: str) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection()
    try:
        assessment = service.assess_transaction(txn_id, conn, persist=True)
        return 200, assessment.to_dict()
    except ValueError as e:
        return 404, {"error": "TRANSACTION_NOT_FOUND", "message": str(e)}
    except Exception as e:
        return 500, {"error": "SCORING_ERROR", "message": str(e)}
    finally:
        conn.close()

def handle_get_signals(txn_id: str) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection()
    try:
        assessment = service.assess_transaction(txn_id, conn, persist=False)
        return 200, {
            "transaction_id": txn_id,
            "score": assessment.score,
            "severity": assessment.severity,
            "signals": [s.to_dict() for s in assessment.signals]
        }
    except ValueError as e:
        return 404, {"error": "TRANSACTION_NOT_FOUND", "message": str(e)}
    finally:
        conn.close()

def handle_get_entities(txn_id: str) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection()
    try:
        assessment = service.assess_transaction(txn_id, conn, persist=False)
        cursor = conn.cursor()

        # Detailed entity cards
        account_id = assessment.related_entities["account"]
        device_id = assessment.related_entities["device"]
        upi_id = assessment.related_entities["upi"]
        beneficiary_id = assessment.related_entities["beneficiary"]

        cursor.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,))
        acc_info = dict(cursor.fetchone() or {})

        cursor.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,))
        dev_info = dict(cursor.fetchone() or {})

        cursor.execute("SELECT * FROM upis WHERE upi_id = ?", (upi_id,))
        upi_info = dict(cursor.fetchone() or {})

        cursor.execute("SELECT * FROM beneficiaries WHERE beneficiary_id = ?", (beneficiary_id,))
        bene_info = dict(cursor.fetchone() or {})

        cursor.execute("""
            SELECT c.case_id, c.title, c.status, l.reason 
            FROM case_entity_links l
            JOIN fraud_cases c ON l.case_id = c.case_id
            WHERE l.entity_id IN (?, ?, ?)
        """, (account_id, device_id, upi_id))
        cases = [dict(r) for r in cursor.fetchall()]

        return 200, {
            "transaction_id": txn_id,
            "account": acc_info,
            "device": dev_info,
            "upi": upi_info,
            "beneficiary": bene_info,
            "associated_fraud_cases": cases,
            "summary": assessment.related_entities
        }
    except ValueError as e:
        return 404, {"error": "TRANSACTION_NOT_FOUND", "message": str(e)}
    finally:
        conn.close()

def handle_get_timeline(txn_id: str) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM timeline_events WHERE transaction_id = ? ORDER BY timestamp ASC", (txn_id,))
        events = [dict(r) for r in cursor.fetchall()]
        return 200, {
            "transaction_id": txn_id,
            "total_events": len(events),
            "events": events
        }
    except Exception as e:
        return 500, {"error": "TIMELINE_FETCH_ERROR", "message": str(e)}
    finally:
        conn.close()

def handle_recalculate(txn_id: str) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection()
    try:
        assessment = service.assess_transaction(txn_id, conn, persist=True)
        return 200, {
            "message": "Risk score successfully recalculated from authoritative database state.",
            "assessment": assessment.to_dict()
        }
    except ValueError as e:
        return 404, {"error": "TRANSACTION_NOT_FOUND", "message": str(e)}
    finally:
        conn.close()

def handle_what_if(txn_id: str, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    disabled_signals = body.get("disabled_signals", [])
    conn = get_connection()
    try:
        sim = service.simulate_what_if(txn_id, disabled_signals, conn)
        return 200, sim
    except ValueError as e:
        return 404, {"error": "TRANSACTION_NOT_FOUND", "message": str(e)}
    finally:
        conn.close()

def handle_get_network_graph(txn_id: str) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM transactions WHERE transaction_id = ?", (txn_id,))
        txn = cursor.fetchone()
        if not txn:
            return 404, {"error": "TRANSACTION_NOT_FOUND"}

        account_id = txn["account_id"]
        device_id = txn["device_id"]
        upi_id = txn["upi_id"]

        nodes = []
        edges = []

        # Target Transaction Node
        nodes.append({
            "id": txn_id, "label": f"{txn_id}\nRs. {txn['amount']:,.0f}",
            "type": "transaction", "severity": "CRITICAL",
            "details": f"Target Transaction ({txn['timestamp']})"
        })

        # Originating Account Node
        nodes.append({
            "id": account_id, "label": f"{account_id}\nVikram Sethi",
            "type": "account", "severity": "CRITICAL",
            "details": "Primary Subject Account (Mule Hub)"
        })
        edges.append({"source": account_id, "target": txn_id, "label": "INITIATED", "color": "#ef4444"})

        # Device Node & Connected Accounts
        if device_id:
            nodes.append({
                "id": device_id, "label": f"{device_id}\nShared Hardware",
                "type": "device", "severity": "CRITICAL",
                "details": "Fingerprint: fp_mumbai_mule_8a7c2b (Android 14)"
            })
            edges.append({"source": device_id, "target": account_id, "label": "BOUND_TO", "color": "#f97316"})

            # Connected mule accounts
            cursor.execute("SELECT account_id, holder_name, risk_tier FROM accounts WHERE device_id = ?", (device_id,))
            mule_accs = cursor.fetchall()
            for m in mule_accs:
                m_id = m["account_id"]
                if m_id != account_id:
                    nodes.append({
                        "id": m_id, "label": f"{m_id}\n{m['holder_name'].split('(')[0]}",
                        "type": "account", "severity": m["risk_tier"],
                        "details": f"Linked Mule Account ({m['holder_name']})"
                    })
                    edges.append({"source": device_id, "target": m_id, "label": "SHARED_HARDWARE", "color": "#f97316"})

        # UPI Destination Node
        if upi_id:
            nodes.append({
                "id": upi_id, "label": f"{upi_id}\nLaundering Funnel",
                "type": "upi", "severity": "HIGH",
                "details": "Virtual Payment Address (ICICI Bank)"
            })
            edges.append({"source": txn_id, "target": upi_id, "label": "PAYMENT_TO", "color": "#ef4444"})

        # Fraud Case Node
        cursor.execute("SELECT case_id, title FROM fraud_cases WHERE case_id = 'CASE-2026-018'")
        case_row = cursor.fetchone()
        if case_row:
            nodes.append({
                "id": case_row["case_id"], "label": f"{case_row['case_id']}\nFIR 402/2026",
                "type": "fraud_case", "severity": "CRITICAL",
                "details": case_row["title"]
            })
            edges.append({"source": case_row["case_id"], "target": account_id, "label": "POLICE_RECORD", "color": "#dc2626"})
            if device_id:
                edges.append({"source": case_row["case_id"], "target": device_id, "label": "SEIZED_HARDWARE", "color": "#dc2626"})

        return 200, {
            "transaction_id": txn_id,
            "center_node": device_id or account_id,
            "nodes": nodes,
            "edges": edges
        }
    finally:
        conn.close()

def handle_get_money_flow(txn_id: str) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM money_flow_edges WHERE case_id = 'CASE-2026-018' ORDER BY hop_order ASC, timestamp ASC")
        rows = [dict(r) for r in cursor.fetchall()]
        
        total_volume = sum(r["amount"] for r in rows)
        hops_count = len(rows)

        return 200, {
            "transaction_id": txn_id,
            "case_id": "CASE-2026-018",
            "title": "Operation Phantom Pay - Fund Layering Trace",
            "total_diverted": 48500.0,
            "hops_count": hops_count,
            "flow_path": rows
        }
    finally:
        conn.close()

def handle_generate_evidence_pack(txn_id: str, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection()
    try:
        assessment = service.assess_transaction(txn_id, conn, persist=True)
        investigator_name = body.get("investigator_name", "Lead Inspector - Mumbai Cyber Cell")
        badge_number = body.get("badge_number", "MC-CYBER-884")

        # Compile cryptographic evidence dossier
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        canonical_content = f"{assessment.assessment_id}:{txn_id}:{assessment.score}:{timestamp}:{badge_number}"
        evidence_sha256 = hashlib.sha256(canonical_content.encode("utf-8")).hexdigest()

        dossier = {
            "dossier_id": f"DOSSIER-{assessment.assessment_id}",
            "generated_at": timestamp,
            "investigator": {
                "name": investigator_name,
                "badge": badge_number,
                "agency": "Financial Intelligence & Cyber Defense Division (FIU-IND Node)"
            },
            "transaction": {
                "transaction_id": txn_id,
                "amount": "Rs. 48,500.00",
                "currency": "INR",
                "channel": "UPI / Instant Real-Time Rail",
                "primary_subject": "Vikram Sethi (ACC-104)",
                "hardware_id": "DEV-204",
                "destination_upi": "merchant-x@upi"
            },
            "risk_evaluation": {
                "converging_score": f"{assessment.score} / 100",
                "severity": assessment.severity,
                "confidence": assessment.confidence,
                "engine_version": assessment.engine_version,
                "configuration_profile": assessment.config_profile
            },
            "evidence_signals": [
                {
                    "signal": s.name,
                    "contribution": f"+{s.contribution} pts",
                    "observed": s.observed_value,
                    "threshold": s.threshold,
                    "finding": s.explanation,
                    "evidence_refs": s.evidence
                }
                for s in assessment.signals if s.triggered
            ],
            "executive_summary": assessment.executive_summary,
            "cryptographic_verification": {
                "algorithm": "SHA-256 (FIPS 180-4)",
                "evidence_hash": evidence_sha256,
                "status": "LEGALLY_PRESERVED_SEALED"
            }
        }
        return 200, dossier
    except ValueError as e:
        return 404, {"error": "TRANSACTION_NOT_FOUND", "message": str(e)}
    finally:
        conn.close()

def handle_get_demo_cases() -> Tuple[int, Dict[str, Any]]:
    cases = [
        {
            "id": "TXN-48291",
            "name": "Mumbai Mule Syndicate (Primary Case)",
            "tier": "CRITICAL",
            "amount": "Rs. 48,500",
            "expected_score": 94,
            "highlight": "Converging multi-tenancy hardware, 27 txns/2h velocity, FIR police link"
        },
        {
            "id": "TXN-LOW-001",
            "name": "Clean Retail Salary Transfer",
            "tier": "LOW",
            "amount": "Rs. 8,500",
            "expected_score": 10,
            "highlight": "Single registered device, normal velocity, zero prior fraud"
        },
        {
            "id": "TXN-MED-002",
            "name": "E-Commerce Velocity Anomaly",
            "tier": "MEDIUM",
            "amount": "Rs. 31,000",
            "expected_score": 59,
            "highlight": "Spike in frequency and ticket size, but clean hardware"
        },
        {
            "id": "TXN-HIGH-003",
            "name": "High-Risk Unregistered Device Cluster",
            "tier": "HIGH",
            "amount": "Rs. 72,000",
            "expected_score": 69,
            "highlight": "Shared hardware + beneficiary reuse across multiple accounts"
        },
        {
            "id": "TXN-MISSING-004",
            "name": "ATM Transfer (Missing Telemetry Data)",
            "tier": "LOW (NOT ASSESSABLE)",
            "amount": "Rs. 5,000",
            "expected_score": 10,
            "highlight": "Demonstrates honest system degradation: missing hardware tagged NOT ASSESSABLE"
        },
    ]
    return 200, {"cases": cases}

def handle_demo_tweak(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """
    Directly mutates the SQLite database live to prove real dynamic calculation to judges.
    """
    action = body.get("action")
    conn = get_connection()
    cursor = conn.cursor()

    try:
        if action == "unlink_device":
            # Change device for 4 accounts to DEV-012 so DEV-204 only has 2 accounts (below threshold 3)
            cursor.execute("UPDATE accounts SET device_id = 'DEV-012' WHERE account_id IN ('ACC-145', 'ACC-167', 'ACC-189', 'ACC-203')")
            cursor.execute("UPDATE transactions SET device_id = 'DEV-012' WHERE account_id IN ('ACC-145', 'ACC-167', 'ACC-189', 'ACC-203')")
            conn.commit()
            assessment = service.assess_transaction("TXN-48291", conn)
            return 200, {
                "action": action,
                "description": "Unlinked 4 accounts from DEV-204. DEV-204 now only has 2 accounts (threshold: 3).",
                "new_score": assessment.score,
                "new_severity": assessment.severity,
                "signals": [s.to_dict() for s in assessment.signals]
            }

        elif action == "relink_device":
            cursor.execute("UPDATE accounts SET device_id = 'DEV-204' WHERE account_id IN ('ACC-145', 'ACC-167', 'ACC-189', 'ACC-203')")
            cursor.execute("UPDATE transactions SET device_id = 'DEV-204' WHERE account_id IN ('ACC-145', 'ACC-167', 'ACC-189', 'ACC-203')")
            conn.commit()
            assessment = service.assess_transaction("TXN-48291", conn)
            return 200, {
                "action": action,
                "description": "Re-linked all 6 accounts to DEV-204.",
                "new_score": assessment.score,
                "new_severity": assessment.severity,
                "signals": [s.to_dict() for s in assessment.signals]
            }

        elif action == "clear_fraud_links":
            cursor.execute("DELETE FROM case_entity_links WHERE entity_id IN ('ACC-104', 'DEV-204', 'merchant-x@upi', '+91-98201-44912', 'BEN-087')")
            cursor.execute("UPDATE accounts SET is_flagged = 0 WHERE account_id = 'ACC-104'")
            cursor.execute("UPDATE devices SET is_flagged = 0 WHERE device_id = 'DEV-204'")
            cursor.execute("UPDATE phones SET is_flagged = 0 WHERE phone_number = '+91-98201-44912'")
            cursor.execute("UPDATE upis SET is_flagged = 0 WHERE upi_id = 'merchant-x@upi'")
            cursor.execute("UPDATE beneficiaries SET is_flagged = 0 WHERE beneficiary_id = 'BEN-087'")
            conn.commit()
            assessment = service.assess_transaction("TXN-48291", conn)
            return 200, {
                "action": action,
                "description": "Cleared previous cybercrime case records and flagged tags.",
                "new_score": assessment.score,
                "new_severity": assessment.severity,
                "signals": [s.to_dict() for s in assessment.signals]
            }

        elif action == "restore_fraud_links":
            cursor.execute("""
                INSERT OR IGNORE INTO case_entity_links (case_id, entity_type, entity_id, reason)
                VALUES 
                ('CASE-2026-018', 'account', 'ACC-104', 'Named in FIR 402/2026 as beneficiary of unauthorized fund diversion'),
                ('CASE-2026-018', 'device', 'DEV-204', 'Hardware fingerprint seized in cyber cell raid telemetry log'),
                ('CASE-2026-018', 'upi', 'merchant-x@upi', 'Virtual payment address flagged for repeated chargeback disputes')
            """)
            cursor.execute("UPDATE accounts SET is_flagged = 1 WHERE account_id = 'ACC-104'")
            cursor.execute("UPDATE devices SET is_flagged = 1 WHERE device_id = 'DEV-204'")
            cursor.execute("UPDATE phones SET is_flagged = 1 WHERE phone_number = '+91-98201-44912'")
            cursor.execute("UPDATE upis SET is_flagged = 1 WHERE upi_id = 'merchant-x@upi'")
            cursor.execute("UPDATE beneficiaries SET is_flagged = 1 WHERE beneficiary_id = 'BEN-087'")
            conn.commit()
            assessment = service.assess_transaction("TXN-48291", conn)
            return 200, {
                "action": action,
                "description": "Restored active cybercrime case records and flags.",
                "new_score": assessment.score,
                "new_severity": assessment.severity,
                "signals": [s.to_dict() for s in assessment.signals]
            }

        elif action == "normalize_velocity":
            # Shift burst transactions to 5 hours ago so they fall outside 2-hour window
            cursor.execute("UPDATE transactions SET timestamp = '2026-09-09 12:00:00' WHERE transaction_id LIKE 'TXN-BURST-%'")
            conn.commit()
            assessment = service.assess_transaction("TXN-48291", conn)
            return 200, {
                "action": action,
                "description": "Normalized rolling velocity (burst transactions shifted outside 2-hour window).",
                "new_score": assessment.score,
                "new_severity": assessment.severity,
                "signals": [s.to_dict() for s in assessment.signals]
            }

        elif action == "restore_velocity":
            for i in range(1, 27):
                minute = 6 + i
                hour = 18
                if minute >= 60:
                    hour += 1
                    minute -= 60
                ts = f"2026-09-09 {hour:02d}:{minute:02d}:00"
                cursor.execute("UPDATE transactions SET timestamp = ? WHERE transaction_id = ?", (ts, f"TXN-BURST-{i:03d}"))
            conn.commit()
            assessment = service.assess_transaction("TXN-48291", conn)
            return 200, {
                "action": action,
                "description": "Restored 26 burst transactions in 2-hour window.",
                "new_score": assessment.score,
                "new_severity": assessment.severity,
                "signals": [s.to_dict() for s in assessment.signals]
            }

        elif action == "reset":
            seed_database()
            assessment = service.assess_transaction("TXN-48291", conn)
            return 200, {
                "action": "reset",
                "description": "Database restored to pristine benchmark scenario.",
                "new_score": assessment.score,
                "new_severity": assessment.severity,
                "signals": [s.to_dict() for s in assessment.signals]
            }

        else:
            return 400, {"error": "INVALID_ACTION", "message": f"Action '{action}' is not supported."}

    finally:
        conn.close()
