// Safe Go handlers — parameterized queries, argv exec (no shell), validated
// paths. Must produce ZERO findings.
package safe

import (
	"database/sql"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

var db *sql.DB

// Parameterized query — placeholder + arg, not string-built.
func GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, _ := db.Query("SELECT * FROM users WHERE id = $1", id)
	_ = rows
}

// exec without a shell — argv form, user input is a bare argument.
func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	exec.Command("ping", "-c1", host).Run()
}

// Path traversal defused with filepath.Base before open.
func Download(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("file"))
	f, _ := os.Open(filepath.Join("/data", name))
	_ = f
}

// Static markup cast to template.HTML is the intentional, safe use — a string
// literal, not user input, so it must NOT be flagged as XSS.
func Banner() template.HTML {
	return template.HTML("<b>Welcome</b>")
}
