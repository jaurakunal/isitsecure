"""GoRouteMapper — route extraction across Go web frameworks."""

from __future__ import annotations

from isitsecure.engine.code_analysis.go_route_mapper import GoRouteMapper


def _write(tmp_path, name, src):
    (tmp_path / name).write_text(src)


def _by_pattern(routes):
    return {r.route_pattern: r for r in routes}


def test_gin_verbs_and_group_prefix(tmp_path):
    _write(tmp_path, "main.go", """
package main
import "github.com/gin-gonic/gin"
func main() {
    r := gin.Default()
    r.GET("/health", healthHandler)
    api := r.Group("/api/v1")
    api.Use(AuthMiddleware())
    api.GET("/users/:id", getUser)
    api.POST("/users", createUser)
}
""")
    routes = _by_pattern(GoRouteMapper().map_routes(str(tmp_path)))
    assert "/health" in routes
    assert routes["/health"].http_methods == ["GET"]
    # group prefix is prepended
    assert "/api/v1/users/:id" in routes
    assert routes["/api/v1/users/:id"].http_methods == ["GET"]
    assert "/api/v1/users" in routes
    assert routes["/api/v1/users"].http_methods == ["POST"]


def test_net_http_handlefunc_is_any_method(tmp_path):
    _write(tmp_path, "srv.go", """
package main
import "net/http"
func setup(mux *http.ServeMux) {
    mux.HandleFunc("/legacy/status", statusHandler)
}
""")
    routes = _by_pattern(GoRouteMapper().map_routes(str(tmp_path)))
    assert "/legacy/status" in routes
    assert routes["/legacy/status"].http_methods == ["ANY"]


def test_chi_title_case_verbs(tmp_path):
    _write(tmp_path, "chi.go", """
package main
func routes(r chi.Router) {
    r.Get("/items", listItems)
    r.Delete("/items/{id}", deleteItem)
}
""")
    routes = _by_pattern(GoRouteMapper().map_routes(str(tmp_path)))
    assert routes["/items"].http_methods == ["GET"]
    # chi's {id} is normalized to the standard :param form
    assert routes["/items/:id"].http_methods == ["DELETE"]


def test_auth_detected_at_file_level(tmp_path):
    _write(tmp_path, "auth.go", """
package main
func routes(r *gin.Engine) {
    r.Use(AuthMiddleware())
    r.GET("/me", currentUser)
}
""")
    routes = GoRouteMapper().map_routes(str(tmp_path))
    assert routes and routes[0].has_auth_check is True


def test_no_auth_signal_means_false(tmp_path):
    _write(tmp_path, "open.go", """
package main
func routes(r *gin.Engine) {
    r.GET("/open", openHandler)
}
""")
    routes = GoRouteMapper().map_routes(str(tmp_path))
    assert routes and routes[0].has_auth_check is False


def test_test_files_are_skipped(tmp_path):
    _write(tmp_path, "handlers_test.go", """
package main
func TestX(t *testing.T) { r.GET("/should-not-appear", h) }
""")
    assert GoRouteMapper().map_routes(str(tmp_path)) == []


def test_backtick_raw_string_path(tmp_path):
    _write(tmp_path, "raw.go", """
package main
func routes(e *echo.Echo) {
    e.GET(`/raw/path`, h)
}
""")
    routes = _by_pattern(GoRouteMapper().map_routes(str(tmp_path)))
    assert "/raw/path" in routes


def test_non_route_go_file_is_ignored(tmp_path):
    _write(tmp_path, "model.go", "package main\ntype User struct { ID int }\n")
    assert GoRouteMapper().map_routes(str(tmp_path)) == []
