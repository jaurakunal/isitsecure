"""Tests for SpringRouteMapper."""

import pytest

from isitsecure.engine.code_analysis.spring_route_mapper import SpringRouteMapper


@pytest.fixture
def mapper():
    return SpringRouteMapper()


class TestBasicRoutes:
    def test_detects_get_mapping(self, mapper, tmp_path):
        (tmp_path / "UserController.java").write_text("""
@RestController
@RequestMapping("/api/users")
public class UserController {
    @GetMapping("/{id}")
    public User getUser(@PathVariable Long id) {
        return userService.findById(id);
    }
}
""")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].route_pattern == "/api/users/:id"
        assert routes[0].http_methods == ["GET"]

    def test_detects_multiple_methods(self, mapper, tmp_path):
        (tmp_path / "TaskController.java").write_text("""
@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @GetMapping("/")
    public List<Task> list() { return null; }

    @PostMapping("/")
    public Task create() { return null; }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {}
}
""")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 3
        methods = {r.http_methods[0] for r in routes}
        assert methods == {"GET", "POST", "DELETE"}

    def test_detects_put_and_patch(self, mapper, tmp_path):
        (tmp_path / "Controller.java").write_text("""
@RestController
@RequestMapping("/api/items")
public class ItemController {
    @PutMapping("/{id}")
    public Item update() { return null; }

    @PatchMapping("/{id}")
    public Item patch() { return null; }
}
""")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 2
        methods = {r.http_methods[0] for r in routes}
        assert "PUT" in methods
        assert "PATCH" in methods


class TestClassPrefix:
    def test_combines_class_and_method_paths(self, mapper, tmp_path):
        (tmp_path / "Controller.java").write_text("""
@RestController
@RequestMapping("/api/v2")
public class ApiController {
    @GetMapping("/health")
    public String health() { return "ok"; }
}
""")
        routes = mapper.map_routes(str(tmp_path))
        assert routes[0].route_pattern == "/api/v2/health"

    def test_no_class_prefix(self, mapper, tmp_path):
        (tmp_path / "Controller.java").write_text("""
@RestController
public class RootController {
    @GetMapping("/status")
    public String status() { return "ok"; }
}
""")
        routes = mapper.map_routes(str(tmp_path))
        assert routes[0].route_pattern == "/status"


class TestPathVariables:
    def test_converts_simple_path_variable(self, mapper):
        assert SpringRouteMapper._normalize_pattern("/{id}") == "/:id"

    def test_converts_typed_path_variable(self, mapper):
        assert SpringRouteMapper._normalize_pattern("/{id:\\d+}") == "/:id"

    def test_multiple_variables(self, mapper):
        assert SpringRouteMapper._normalize_pattern("/users/{userId}/tasks/{taskId}") == "/users/:userId/tasks/:taskId"


class TestAuthDetection:
    def test_detects_pre_authorize(self, mapper, tmp_path):
        (tmp_path / "Controller.java").write_text("""
@RestController
@RequestMapping("/api/admin")
public class AdminController {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public List<User> getUsers() { return null; }
}
""")
        routes = mapper.map_routes(str(tmp_path))
        assert routes[0].has_auth_check is True

    def test_detects_secured(self, mapper, tmp_path):
        (tmp_path / "Controller.java").write_text("""
@RestController
@Secured("ROLE_USER")
public class SecuredController {
    @GetMapping("/data")
    public String data() { return null; }
}
""")
        routes = mapper.map_routes(str(tmp_path))
        assert routes[0].has_auth_check is True

    def test_no_auth(self, mapper, tmp_path):
        (tmp_path / "Controller.java").write_text("""
@RestController
public class PublicController {
    @GetMapping("/public")
    public String pub() { return null; }
}
""")
        routes = mapper.map_routes(str(tmp_path))
        assert routes[0].has_auth_check is False


class TestKotlinSupport:
    def test_detects_kotlin_routes(self, mapper, tmp_path):
        (tmp_path / "UserController.kt").write_text("""
@RestController
@RequestMapping("/api/users")
class UserController {
    @GetMapping("/{id}")
    fun getUser(@PathVariable id: Long): User = userService.findById(id)

    @PostMapping("/")
    fun createUser(@RequestBody user: User): User = userService.save(user)
}
""")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 2


class TestSkipDirs:
    def test_skips_target(self, mapper, tmp_path):
        target_dir = tmp_path / "target" / "classes"
        target_dir.mkdir(parents=True)
        (target_dir / "Controller.java").write_text("""
@RestController
public class C { @GetMapping("/t") public void t() {} }
""")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 0

    def test_skips_test_dir(self, mapper, tmp_path):
        test_dir = tmp_path / "test" / "java"
        test_dir.mkdir(parents=True)
        (test_dir / "Controller.java").write_text("""
@RestController
public class C { @GetMapping("/t") public void t() {} }
""")
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 0
