"""Tests for FastAPIRouteMapper."""

import pytest

from isitsecure.engine.code_analysis.fastapi_route_mapper import FastAPIRouteMapper


@pytest.fixture
def mapper():
    return FastAPIRouteMapper()


class TestFastAPIRoutes:
    def test_detects_decorator_routes(self, mapper, tmp_path):
        (tmp_path / "main.py").write_text("""
from fastapi import FastAPI
app = FastAPI()

@app.get("/tasks")
async def list_tasks():
    pass

@app.post("/tasks")
async def create_task():
    pass

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: str):
    pass
""")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 3
        methods = [r.http_methods[0] for r in routes]
        assert "GET" in methods
        assert "POST" in methods
        assert "DELETE" in methods

    def test_normalizes_path_params(self, mapper, tmp_path):
        (tmp_path / "main.py").write_text("""
from fastapi import FastAPI
app = FastAPI()

@app.get("/users/{user_id}/tasks/{task_id}")
async def get_task():
    pass
""")
        routes = mapper.map_routes(str(tmp_path))
        assert routes[0].route_pattern == "/users/:user_id/tasks/:task_id"

    def test_detects_router_prefix(self, mapper, tmp_path):
        (tmp_path / "routes.py").write_text("""
from fastapi import APIRouter
router = APIRouter(prefix="/api/v1")

@router.get("/users")
async def list_users():
    pass
""")
        routes = mapper.map_routes(str(tmp_path))
        assert routes[0].route_pattern == "/api/v1/users"


class TestFlaskRoutes:
    def test_detects_flask_route(self, mapper, tmp_path):
        (tmp_path / "app.py").write_text("""
from flask import Flask
app = Flask(__name__)

@app.route('/tasks', methods=['GET', 'POST'])
def tasks():
    pass
""")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert "GET" in routes[0].http_methods
        assert "POST" in routes[0].http_methods

    def test_flask_default_get(self, mapper, tmp_path):
        (tmp_path / "app.py").write_text("""
from flask import Flask
app = Flask(__name__)

@app.route('/health')
def health():
    pass
""")
        routes = mapper.map_routes(str(tmp_path))
        assert routes[0].http_methods == ["GET"]


class TestAuthDetection:
    def test_detects_depends_auth(self, mapper, tmp_path):
        (tmp_path / "main.py").write_text("""
from fastapi import FastAPI, Depends
app = FastAPI()

@app.get("/profile")
async def get_profile(user=Depends(get_current_user)):
    pass
""")
        routes = mapper.map_routes(str(tmp_path))
        assert routes[0].has_auth_check is True

    def test_detects_oauth2(self, mapper, tmp_path):
        (tmp_path / "main.py").write_text("""
from fastapi import FastAPI
from fastapi.security import OAuth2PasswordBearer
app = FastAPI()
oauth2 = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/tasks")
async def list_tasks():
    pass
""")
        routes = mapper.map_routes(str(tmp_path))
        assert routes[0].has_auth_check is True

    def test_no_auth_detected(self, mapper, tmp_path):
        (tmp_path / "main.py").write_text("""
from fastapi import FastAPI
app = FastAPI()

@app.get("/public")
async def public():
    pass
""")
        routes = mapper.map_routes(str(tmp_path))
        assert routes[0].has_auth_check is False


class TestSkipDirs:
    def test_skips_venv(self, mapper, tmp_path):
        venv_dir = tmp_path / "venv" / "lib"
        venv_dir.mkdir(parents=True)
        (venv_dir / "routes.py").write_text("@app.get('/test')\nasync def t(): pass")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 0

    def test_skips_non_route_files(self, mapper, tmp_path):
        (tmp_path / "models.py").write_text("class Task: pass")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 0


class TestNormalization:
    def test_adds_leading_slash(self):
        from isitsecure.engine.code_analysis.shared_utils import normalize_route_pattern
        assert normalize_route_pattern("tasks") == "/tasks"

    def test_converts_curly_params(self):
        from isitsecure.engine.code_analysis.shared_utils import normalize_route_pattern
        assert normalize_route_pattern("/users/{id}") == "/users/:id"

    def test_converts_flask_params(self):
        from isitsecure.engine.code_analysis.shared_utils import normalize_route_pattern
        assert normalize_route_pattern("/users/<int:id>") == "/users/:id"
