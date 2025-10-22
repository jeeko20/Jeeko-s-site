import pytest
from types import SimpleNamespace

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app


class DummyObj:
    def __init__(self, user_id):
        self.user_id = user_id

    def __repr__(self):
        return f"DummyObj(user_id={self.user_id})"


@pytest.fixture
def client():
    app.config['TESTING'] = True
    # Disable Flask-Login checks for tests (we simulate authentication via monkeypatch)
    with app.app_context():
        app.config['LOGIN_DISABLED'] = True
        with app.test_client() as client:
            yield client
        app.config['LOGIN_DISABLED'] = False


def test_delete_comment_as_owner(monkeypatch, client):
    # emulate Comment.query.get_or_404 returning object
    dummy = SimpleNamespace(user_id=1)

    def fake_get_or_404(cid):
        assert cid == 123
        return dummy

    monkeypatch.setattr('app.Comment', SimpleNamespace(query=SimpleNamespace(get_or_404=fake_get_or_404)))

    # patch current_user
    monkeypatch.setattr('app.current_user', SimpleNamespace(id=1, is_authenticated=True))

    # patch db.session.delete/commit to no-op
    monkeypatch.setattr('app.db', SimpleNamespace(session=SimpleNamespace(delete=lambda x: None, commit=lambda : None)))

    resp = client.delete('/api/comment/123')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_delete_comment_not_owner(monkeypatch, client):
    dummy = SimpleNamespace(user_id=2)

    def fake_get_or_404(cid):
        return dummy

    monkeypatch.setattr('app.Comment', SimpleNamespace(query=SimpleNamespace(get_or_404=fake_get_or_404)))
    monkeypatch.setattr('app.current_user', SimpleNamespace(id=1, is_authenticated=True))

    resp = client.delete('/api/comment/999')
    assert resp.status_code == 403


def test_delete_ressource_as_owner(monkeypatch, client):
    dummy = SimpleNamespace(user_id=5, id=77)

    def fake_get_or_404(rid):
        assert rid == 77
        return dummy

    monkeypatch.setattr('app.Ressource', SimpleNamespace(query=SimpleNamespace(get_or_404=fake_get_or_404)))
    monkeypatch.setattr('app.current_user', SimpleNamespace(id=5, is_authenticated=True))
    monkeypatch.setattr('app.db', SimpleNamespace(session=SimpleNamespace(delete=lambda x: None, commit=lambda : None)))

    resp = client.delete('/api/ressource/77')
    assert resp.status_code == 200
    assert resp.get_json().get('success') is True


def test_delete_ressource_not_owner(monkeypatch, client):
    dummy = SimpleNamespace(user_id=9)

    def fake_get_or_404(rid):
        return dummy

    monkeypatch.setattr('app.Ressource', SimpleNamespace(query=SimpleNamespace(get_or_404=fake_get_or_404)))
    monkeypatch.setattr('app.current_user', SimpleNamespace(id=1, is_authenticated=True))

    resp = client.delete('/api/ressource/1')
    assert resp.status_code == 403
