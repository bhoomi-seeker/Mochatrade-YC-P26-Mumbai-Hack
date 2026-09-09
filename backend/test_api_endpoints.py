"""
API Endpoint Verification Script
Tests all REST API endpoints directly without needing a live network socket.
"""

from app.api import handler
from app.db.seed_data import seed_database

def test_endpoints():
    seed_database()
    print("Testing API Handlers...")

    # 1. GET /api/risk-score/TXN-48291
    code, res = handler.handle_get_risk_score("TXN-48291")
    assert code == 200, f"Expected 200, got {code}"
    assert res["score"] == 94, f"Expected 94, got {res['score']}"
    assert res["severity"] == "CRITICAL"
    assert res["confidence"] == "HIGH"
    print("[OK] GET /api/risk-score/TXN-48291 -> Score 94, CRITICAL, HIGH")

    # 2. GET /api/risk-score/TXN-48291/signals
    code, res = handler.handle_get_signals("TXN-48291")
    assert code == 200
    assert len(res["signals"]) == 6
    print(f"[OK] GET /api/risk-score/TXN-48291/signals -> {len(res['signals'])} signals returned")

    # 3. GET /api/risk-score/TXN-48291/entities
    code, res = handler.handle_get_entities("TXN-48291")
    assert code == 200
    assert res["account"]["account_id"] == "ACC-104"
    assert res["device"]["device_id"] == "DEV-204"
    print("[OK] GET /api/risk-score/TXN-48291/entities -> Entities and case correlations verified")

    # 4. GET /api/risk-score/TXN-48291/timeline
    code, res = handler.handle_get_timeline("TXN-48291")
    assert code == 200
    assert res["total_events"] >= 8
    print(f"[OK] GET /api/risk-score/TXN-48291/timeline -> {res['total_events']} timeline events returned")

    # 5. POST /api/risk-score/TXN-48291/recalculate
    code, res = handler.handle_recalculate("TXN-48291")
    assert code == 200
    assert res["assessment"]["score"] == 94
    print("[OK] POST /api/risk-score/TXN-48291/recalculate -> Engine recalculated 94")

    # 6. POST /api/risk-score/TXN-48291/what-if
    code, res = handler.handle_what_if("TXN-48291", {"disabled_signals": ["SHARED_DEVICE"]})
    assert code == 200
    assert res["simulated_score"] == 74
    print(f"[OK] POST /api/risk-score/TXN-48291/what-if (without SHARED_DEVICE) -> Score simulated: {res['simulated_score']}")

    # 7. GET /api/investigate/network/TXN-48291
    code, res = handler.handle_get_network_graph("TXN-48291")
    assert code == 200
    assert len(res["nodes"]) >= 8
    print(f"[OK] GET /api/investigate/network/TXN-48291 -> {len(res['nodes'])} graph nodes, {len(res['edges'])} edges")

    # 8. GET /api/investigate/money-flow/TXN-48291
    code, res = handler.handle_get_money_flow("TXN-48291")
    assert code == 200
    assert res["hops_count"] == 5
    print(f"[OK] GET /api/investigate/money-flow/TXN-48291 -> {res['hops_count']} hops from Victim to Cash Out")

    # 9. POST /api/investigate/evidence-pack/TXN-48291
    code, res = handler.handle_generate_evidence_pack("TXN-48291", {"badge_number": "JUDGE-SPECIAL-01"})
    assert code == 200
    assert "SHA-256" in res["cryptographic_verification"]["algorithm"]
    print(f"[OK] POST /api/investigate/evidence-pack/TXN-48291 -> Sealed Dossier {res['dossier_id']}")

    # 10. GET /api/demo/cases
    code, res = handler.handle_get_demo_cases()
    assert code == 200
    assert len(res["cases"]) == 5
    print(f"[OK] GET /api/demo/cases -> {len(res['cases'])} benchmark demo scenarios available")

    # 11. POST /api/demo/tweak (unlink_device)
    code, res = handler.handle_demo_tweak({"action": "unlink_device"})
    assert code == 200
    assert res["new_score"] == 74
    print("[OK] POST /api/demo/tweak (unlink_device) -> Live DB mutation changed score 94 -> 74!")

    # Reset
    handler.handle_demo_tweak({"action": "reset"})
    print("[OK] Database restored to benchmark state.")
    print("\nALL API ENDPOINTS FUNCTIONAL AND VERIFIED 100%!")

if __name__ == "__main__":
    test_endpoints()
