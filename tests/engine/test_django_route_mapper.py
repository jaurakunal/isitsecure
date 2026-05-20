"""Tests for DjangoRouteMapper."""

import tempfile
import os
from pathlib import Path

import pytest

from isitsecure.engine.code_analysis.django_route_mapper import DjangoRouteMapper


@pytest.fixture
def mapper():
    return DjangoRouteMapper()


class TestDjangoPathRoutes:
    def test_detects_simple_path(self, mapper, tmp_path):
        (tmp_path / "urls.py").write_text("""
from django.urls import path
from . import views

urlpatterns = [
    path('tasks/', views.task_list),
    path('tasks/<int:pk>/', views.task_detail),
]
""")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 2
        assert routes[0].route_pattern == "/tasks/"
        assert routes[1].route_pattern == "/tasks/:pk/"

    def test_detects_re_path(self, mapper, tmp_path):
        (tmp_path / "urls.py").write_text("""
from django.urls import re_path
urlpatterns = [
    re_path('api/v1/users/', views.users),
]
""")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert "/api/v1/users/" in routes[0].route_pattern

    def test_detects_class_based_view(self, mapper, tmp_path):
        (tmp_path / "urls.py").write_text("""
from django.urls import path
urlpatterns = [
    path('tasks/', TaskListView.as_view()),
]

class TaskListView:
    def get(self, request):
        pass
    def post(self, request):
        pass
""")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert "GET" in routes[0].http_methods
        assert "POST" in routes[0].http_methods


class TestDRFRoutes:
    def test_detects_router_register(self, mapper, tmp_path):
        (tmp_path / "urls.py").write_text("""
from rest_framework.routers import DefaultRouter
router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'tasks', TaskViewSet)
""")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 2
        assert routes[0].route_pattern == "/users/"
        assert routes[1].route_pattern == "/tasks/"
        # DRF viewsets have all methods
        assert "GET" in routes[0].http_methods
        assert "DELETE" in routes[0].http_methods


class TestAuthDetection:
    def test_detects_login_required(self, mapper, tmp_path):
        (tmp_path / "urls.py").write_text("""
from django.contrib.auth.decorators import login_required
urlpatterns = [
    path('profile/', login_required(views.profile)),
]
""")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].has_auth_check is True

    def test_detects_permission_classes(self, mapper, tmp_path):
        (tmp_path / "urls.py").write_text("""
from rest_framework.permissions import IsAuthenticated
urlpatterns = [
    path('tasks/', views.task_list),
]
permission_classes = [IsAuthenticated]
""")
        routes = mapper.map_routes(str(tmp_path))
        assert routes[0].has_auth_check is True

    def test_no_auth_detected(self, mapper, tmp_path):
        (tmp_path / "urls.py").write_text("""
urlpatterns = [
    path('public/', views.public_page),
]
""")
        routes = mapper.map_routes(str(tmp_path))
        assert routes[0].has_auth_check is False


class TestSkipDirs:
    def test_skips_venv(self, mapper, tmp_path):
        venv_dir = tmp_path / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        (venv_dir / "urls.py").write_text("path('test/', views.test)")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 0


class TestNormalization:
    def test_adds_leading_slash(self):
        assert DjangoRouteMapper._normalize_pattern("tasks/") == "/tasks/"

    def test_converts_typed_param(self):
        assert DjangoRouteMapper._normalize_pattern("<int:pk>") == "/:pk"

    def test_converts_untyped_param(self):
        assert DjangoRouteMapper._normalize_pattern("<slug>") == "/:slug"
