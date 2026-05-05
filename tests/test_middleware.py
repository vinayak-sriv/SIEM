import pytest
from unittest.mock import patch, MagicMock
from src.models import Alert
from src.middleware import PythonMiddleware
from src.ollama_service import OllamaService

def test_alert_fingerprint_deduplication():
    raw_1 = {
        "rule": {"id": "123", "level": 10},
        "agent": {"id": "001"},
        "data": {"srcip": "10.0.0.1"},
        "timestamp": "2026-05-05T10:00:00Z"
    }
    raw_2 = {
        "rule": {"id": "123", "level": 10},
        "agent": {"id": "001"},
        "data": {"srcip": "10.0.0.1"},
        "timestamp": "2026-05-05T10:00:00Z"
    }
    raw_diff_time = {
        "rule": {"id": "123", "level": 10},
        "agent": {"id": "001"},
        "data": {"srcip": "10.0.0.1"},
        "timestamp": "2026-05-05T10:00:01Z"
    }
    
    alert_1 = Alert.from_wazuh_json(raw_1)
    alert_2 = Alert.from_wazuh_json(raw_2)
    alert_diff_time = Alert.from_wazuh_json(raw_diff_time)
    
    # Same data must yield same fingerprint
    assert alert_1.alertId == alert_2.alertId
    # Different timestamp must yield different fingerprint
    assert alert_1.alertId != alert_diff_time.alertId

def test_seen_set_bounding_logic():
    config = {
        "wazuh": {"alerts_json_path": "dummy.json"},
        "filter": {"min_severity_level": 5, "dedupe_cache_size": 3},
        "output": {"write_markdown": False},
        "ollama": {"base_url": "http://localhost", "model": "test"}
    }
    middleware = PythonMiddleware(config)
    
    # Fill cache up to size 3
    middleware._remember_alert_id("id1")
    middleware._remember_alert_id("id2")
    middleware._remember_alert_id("id3")
    
    assert len(middleware._seen_ids) == 3
    assert "id1" in middleware._seen_ids
    
    # Push 4th ID, oldest (id1) should be evicted
    middleware._remember_alert_id("id4")
    assert len(middleware._seen_ids) == 3
    assert "id1" not in middleware._seen_ids
    assert "id4" in middleware._seen_ids

def test_ollama_failure_fallback():
    config = {
        "ollama": {
            "base_url": "http://localhost", 
            "model": "test", 
            "max_retries": 1,
            "circuit_breaker_failures": 10
        }
    }
    service = OllamaService(config)
    
    raw = {
        "rule": {"id": "2502", "description": "SSH attack", "level": 12},
        "agent": {"name": "Ubuntu"}
    }
    alert = Alert.from_wazuh_json(raw)
    
    # Mock generate to always raise Exception
    with patch.object(service, 'generate', side_effect=Exception("Mocked network error")):
        enriched = service.enrich_alert(alert)
        
        # It should not crash, and should return a valid EnrichedAlert
        assert enriched.originalAlert.alertId == alert.alertId
        # The explanation should contain fallback logic
        assert "SSH authentication attack against Ubuntu" in enriched.explanation
        assert "Fallback note: Ollama fallback was used because the model call failed: Mocked network error" in enriched.remediation
