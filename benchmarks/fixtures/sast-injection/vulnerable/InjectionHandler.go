// Injection benchmark fixture — Go SQLi, command injection, SSRF, path
// traversal (VULNERABLE). Sources: net/http request objects. `// EXPECT <class>`
// markers are the ground truth for the SAST injection scorer.
package vulnerable

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

var db *sql.DB

// --- SQL injection ---
func GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)) // EXPECT sqli
	_ = rows
}

func SearchUser(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	rows, _ := db.Query("SELECT * FROM users WHERE name = '" + name + "'") // EXPECT sqli
	_ = rows
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := "DELETE FROM users WHERE id = " + id
	db.Exec(query) // EXPECT sqli
}

// --- Command injection ---
func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	exec.Command("sh", "-c", "ping -c1 "+host).Run() // EXPECT command-injection
}

// --- SSRF ---
func Fetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, _ := http.Get(target) // EXPECT ssrf
	_ = resp
}

// --- Path traversal ---
func Download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	f, _ := os.Open("/data/" + name) // EXPECT path-traversal
	_ = f
}
