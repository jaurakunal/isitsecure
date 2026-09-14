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


def test_group_middleware_marks_routes_authed(tmp_path):
    """A router/group with an auth-naming .Use middleware guards its routes."""
    _write(tmp_path, "auth.go", """
package main
func routes(r *gin.Engine) {
    api := r.Group("/api")
    api.Use(AuthMiddleware())
    api.GET("/me", currentUser)
}
""")
    routes = _by_pattern(GoRouteMapper().map_routes(str(tmp_path)))
    assert routes["/api/me"].has_auth_check is True


def test_non_auth_middleware_does_not_credit_auth(tmp_path):
    """A .Use of logging/CORS/recovery must NOT mark routes as authed."""
    _write(tmp_path, "log.go", """
package main
func routes(r *gin.Engine) {
    r.Use(Logger())
    r.Use(gin.Recovery())
    r.GET("/open", openHandler)
}
""")
    routes = _by_pattern(GoRouteMapper().map_routes(str(tmp_path)))
    assert routes["/open"].has_auth_check is False


def test_no_auth_signal_means_false(tmp_path):
    _write(tmp_path, "open.go", """
package main
func routes(r *gin.Engine) {
    r.GET("/open", openHandler)
}
""")
    routes = GoRouteMapper().map_routes(str(tmp_path))
    assert routes and routes[0].has_auth_check is False


def test_handler_source_captured_for_named_handler(tmp_path):
    """The route carries its handler's body so per-route auth can be judged."""
    _write(tmp_path, "h.go", """
package main
import "net/http"
func getThing(w http.ResponseWriter, r *http.Request) {
    if r.Header.Get("Authorization") == "" {
        http.Error(w, "no", http.StatusUnauthorized)
        return
    }
    w.Write([]byte("thing"))
}
func routes(mux *http.ServeMux) {
    mux.HandleFunc("/thing", getThing)
}
""")
    routes = _by_pattern(GoRouteMapper().map_routes(str(tmp_path)))
    body = routes["/thing"].handler_source
    assert "func getThing" in body
    assert "StatusUnauthorized" in body  # brace-matched to the full body


def test_non_route_method_calls_are_not_routes(tmp_path):
    """`r.Header.Get("Authorization")` / `c.Get("user")` have no handler arg,
    so they must not be mapped as routes (a real regression that produced a
    bogus `/Authorization` route)."""
    _write(tmp_path, "h.go", """
package main
import "net/http"
func h(w http.ResponseWriter, r *http.Request) {
    _ = r.Header.Get("Authorization")
    _ = r.URL.Query().Get("id")
}
func routes(mux *http.ServeMux) {
    mux.HandleFunc("/real", h)
}
""")
    routes = _by_pattern(GoRouteMapper().map_routes(str(tmp_path)))
    assert set(routes) == {"/real"}


def test_wrapped_middleware_handler_is_mapped(tmp_path):
    """`router.GET(p, Log(AuthCheck(h)))` — a wrapped handler — is a route, and
    the auth-naming wrapper marks it authed (idiomatic Go middleware chaining)."""
    _write(tmp_path, "app.go", """
package main
func setup(router *httprouter.Router) {
    router.GET("/dash", mw.LoggingMiddleware(mw.AuthCheck(dashHandler)))
    router.GET("/setup", mw.LoggingMiddleware(setupHandler))
}
""")
    routes = _by_pattern(GoRouteMapper().map_routes(str(tmp_path)))
    assert "/dash" in routes and "/setup" in routes
    assert routes["/dash"].has_auth_check is True     # AuthCheck wrapper
    assert routes["/setup"].has_auth_check is False   # only logging


def test_handler_named_with_auth_word_is_not_auto_authed(tmp_path):
    """A handler merely NAMED with an auth-ish word (loginViewHandler,
    getSessionData) must NOT be treated as guarded — that would suppress a real
    missing-auth. Auth is credited only from a wrapping middleware CALL."""
    _write(tmp_path, "app.go", """
package main
func setup(router *httprouter.Router) {
    router.GET("/login", mw.LoggingMiddleware(loginViewHandler))
    router.GET("/session", mw.LoggingMiddleware(getSessionData))
}
""")
    routes = _by_pattern(GoRouteMapper().map_routes(str(tmp_path)))
    assert routes["/login"].has_auth_check is False
    assert routes["/session"].has_auth_check is False


def test_wrapped_handler_body_resolves_to_innermost(tmp_path):
    """handler_source is the innermost real handler's body, not a wrapper."""
    _write(tmp_path, "app.go", """
package main
import "net/http"
func dashHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    w.Write([]byte("dash"))
}
func setup(router *httprouter.Router) {
    router.GET("/dash", mw.Logging(mw.AuthCheck(dashHandler)))
}
""")
    routes = _by_pattern(GoRouteMapper().map_routes(str(tmp_path)))
    assert "func dashHandler" in routes["/dash"].handler_source


def test_inline_handler_is_a_route(tmp_path):
    """An inline func literal handler still counts as a route."""
    _write(tmp_path, "inline.go", """
package main
import "net/http"
func routes(mux *http.ServeMux) {
    mux.HandleFunc("/inline", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("hi"))
    })
}
""")
    routes = _by_pattern(GoRouteMapper().map_routes(str(tmp_path)))
    assert "/inline" in routes


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
