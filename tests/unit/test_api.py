import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.main import app
from app.database.models import Base, Target
from app.database.session import engine


@pytest.fixture(scope="function")
def client():
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    from app.database.session import SessionLocal

    session = SessionLocal()
    yield session
    session.rollback()
    session.close()
    Base.metadata.drop_all(bind=engine)


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_create_target_unauthorized(client):
    response = client.post(
        "/targets",
        json={
            "name": "External API",
            "target_type": "llm",
            "base_url": "https://api.example.com",
            "config": {},
        },
    )
    assert response.status_code == 403


def test_create_target_localhost(client):
    response = client.post(
        "/targets",
        json={
            "name": "Local LLM",
            "target_type": "llm",
            "base_url": "http://localhost:8000",
            "config": {},
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Local LLM"
    assert data["target_type"] == "llm"
    assert data["is_authorized"] is True


def test_list_targets(client):
    client.post(
        "/targets",
        json={
            "name": "Target 1",
            "target_type": "llm",
            "base_url": "http://localhost:8001",
            "config": {},
        },
    )
    client.post(
        "/targets",
        json={
            "name": "Target 2",
            "target_type": "rag",
            "base_url": "http://localhost:8002",
            "config": {},
        },
    )

    response = client.get("/targets")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2


def test_create_scan(client):
    target_response = client.post(
        "/targets",
        json={
            "name": "Scan Target",
            "target_type": "llm",
            "base_url": "http://localhost:8000",
            "config": {},
        },
    )
    target_id = target_response.json()["id"]

    response = client.post(
        "/scans", json={"target_id": target_id, "configuration": {"budget": {"max_requests": 50}}}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["target_id"] == target_id
    assert data["status"] == "PENDING"


def test_create_scan_unauthorized_target(client):
    target = Target(
        name="Unauthorized", target_type="llm", base_url="http://example.com", is_authorized=False
    )
    db = Session(bind=engine)
    db.add(target)
    db.commit()
    db.refresh(target)

    response = client.post("/scans", json={"target_id": target.id})
    assert response.status_code == 403


def test_list_scans(client):
    target_response = client.post(
        "/targets",
        json={
            "name": "Target",
            "target_type": "llm",
            "base_url": "http://localhost:8000",
            "config": {},
        },
    )
    target_id = target_response.json()["id"]

    client.post("/scans", json={"target_id": target_id})
    client.post("/scans", json={"target_id": target_id})

    response = client.get("/scans")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2


def test_get_checklist(client):
    response = client.get("/checklist")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
