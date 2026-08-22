def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_create_target(client, db_session):
    import models
    # Ensure empty DB
    db_session.query(models.Target).delete()
    db_session.commit()
    
    response = client.post("/targets/", json={"hostname": "test.com"})
    assert response.status_code == 201
    data = response.json()
    assert data["hostname"] == "test.com"
    assert "id" in data

def test_trigger_scan_not_found(client):
    response = client.post("/scans/", json={"target_id": 999})
    assert response.status_code == 404

