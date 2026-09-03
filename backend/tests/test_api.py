from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_health():
    assert client.get('/api/health').json()['status'] == 'ok'

def test_rejects_private_target():
    assert client.post('/api/investigations', json={'url': 'http://127.0.0.1'}).status_code == 400

def test_investigation_has_evidence():
    response = client.post('/api/investigations', json={'url': 'https://login-verify.example.com/account'})
    assert response.status_code == 200
    assert response.json()['risk_score'] > 0
    assert response.json()['evidence']

def test_quick_check_is_fast_stage():
    response = client.post('/api/v1/quick-check', json={'url': 'https://example.com'})
    assert response.status_code == 200
    assert response.json()['data']['deep_required'] is False

def test_versioned_report_envelope():
    response = client.post('/api/v1/investigations', json={'url': 'https://example.com'})
    investigation_id = response.json()['data']['id']
    report = client.get(f'/api/v1/investigations/{investigation_id}/report')
    assert report.json()['success'] is True
    assert report.json()['data']['id'] == investigation_id

def test_versioned_investigation_is_queued_contract():
    response = client.post('/api/v1/investigations', json={'url': 'https://example.com'})
    assert response.status_code == 200
    assert response.json()['data']['status'] == 'QUEUED'
    investigation_id = response.json()['data']['id']
    status = client.get(f'/api/v1/investigations/{investigation_id}')
    assert status.json()['data']['status'] in {'ANALYZING', 'COMPLETED'}
