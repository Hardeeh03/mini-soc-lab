from triage_pipeline import decide_severity, enrich_ip


def test_enrich_ip_known_bad():
    rep = enrich_ip("185.244.25.10")
    assert rep["verdict"] == "malicious"
    assert rep["category"] == "brute_force"


def test_enrich_ip_clean():
    rep = enrich_ip("8.8.8.8")
    assert rep["verdict"] == "clean"
    assert rep["score"] == 5


def test_decide_severity_escalates_on_malicious_ip():
    alert = {"alert_name": "Excessive Failed Logins", "severity": "low", "details": ""}
    reputation = enrich_ip("185.244.25.10")
    decision = decide_severity(alert, reputation)
    assert decision["decision"] == "escalate"


def test_decide_severity_escalates_on_high_signal_details():
    alert = {
        "alert_name": "Encoded PowerShell Detected",
        "severity": "medium",
        "details": "powershell.exe -EncodedCommand abcd",
    }
    reputation = enrich_ip("10.0.1.12")
    decision = decide_severity(alert, reputation)
    assert decision["decision"] == "escalate"
    assert "high-signal" in decision["reasons"][0]


def test_decide_severity_auto_closes_clean_low_severity():
    alert = {"alert_name": "Impossible Travel Login", "severity": "medium", "details": "Successful login"}
    reputation = enrich_ip("198.51.100.23")
    decision = decide_severity(alert, reputation)
    assert decision["decision"] == "auto_close"


def test_decide_severity_escalates_on_high_severity_alone():
    alert = {"alert_name": "Port Scan Detected", "severity": "critical", "details": ""}
    reputation = enrich_ip("203.0.113.70")
    decision = decide_severity(alert, reputation)
    assert decision["decision"] == "escalate"
    assert decision["priority"] == "critical"
