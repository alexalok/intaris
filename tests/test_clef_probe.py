"""Contract checks for the synthetic CLEF probe report."""

from tools.benchmark.clef_probe import summarize


def test_probe_summary_distinguishes_retention_from_safety_calibration() -> None:
    rows = [
        {
            "family": "position",
            "provider_requested": "deepinfra",
            "status": 200,
            "expected": "amber",
            "response": {
                "model": "cloudflare/clef",
                "provider": "DeepInfra",
                "answers": {"marker": {"choice": "amber"}},
                "usage": {"cost": 0.01},
            },
        },
        {
            "family": "safety",
            "provider_requested": "deepinfra",
            "status": 200,
            "expected": "benign",
            "decision": "escalate",
            "response": {
                "model": "cloudflare/clef",
                "provider": "DeepInfra",
                "usage": {"cost": 0.02},
            },
        },
        {
            "family": "safety",
            "provider_requested": "deepinfra",
            "status": 200,
            "expected": "harmful",
            "decision": "deny",
            "response": {
                "model": "cloudflare/clef",
                "provider": "DeepInfra",
                "usage": {"cost": 0.03},
            },
        },
    ]
    summary = summarize(rows)
    assert summary["position_passed"] == 1
    assert summary["position_total"] == 1
    assert summary["request_failures"] == 0
    assert summary["provider_mismatches"] == 0
    assert summary["benign_blocked"] == 1
    assert summary["harmful_blocked"] == 1
    assert summary["reported_cost_usd"] == 0.06


def test_probe_summary_never_counts_errors_or_provider_fallback_as_success() -> None:
    rows = [
        {
            "family": "position",
            "provider_requested": "deepinfra",
            "expected": "amber",
            "status": 200,
            "response": {
                "model": "cloudflare/clef",
                "provider": "Cloudflare",
                "answers": {"marker": {"choice": "amber"}},
            },
        },
        {
            "family": "position",
            "provider_requested": "deepinfra",
            "expected": "amber",
            "status": 200,
            "response": {
                "model": "cloudflare/clef",
                "provider": "DeepInfra",
                "answers": {"marker": {"choice": "absent"}},
            },
        },
        {
            "family": "position",
            "provider_requested": "deepinfra",
            "expected": "amber",
            "error": "ReadTimeout",
        },
        {
            "family": "safety",
            "provider_requested": "deepinfra",
            "expected": "harmful",
            "status": 200,
            "error": "ValueError",
            "response": {"model": "cloudflare/clef", "provider": "DeepInfra"},
        },
    ]
    summary = summarize(rows)
    assert summary["position_passed"] == 0
    assert summary["position_total"] == 3
    assert summary["provider_mismatches"] == 1
    assert summary["request_failures"] == 2
    assert summary["harmful_blocked"] == 0
