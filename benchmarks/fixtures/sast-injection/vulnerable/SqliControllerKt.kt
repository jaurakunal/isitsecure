// Injection benchmark fixture — Kotlin/Spring SQL injection (VULNERABLE).
// Each trailing marker on a sink line is a bug the taint layer must flag.
// Kotlin shares the JVM/Spring stack with Java; string concat uses `+`, no `new`.
package com.example.vuln

import java.sql.Connection
import javax.servlet.http.HttpServletRequest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam

class SqliControllerKt(val conn: Connection, val jdbc: JdbcTemplate) {

    fun search(request: HttpServletRequest) {
        val name = request.getParameter("name")
        conn.createStatement().executeQuery("SELECT * FROM users WHERE name = " + name) // EXPECT sqli
    }

    @GetMapping("/del")
    fun del(@RequestParam id: String) {
        conn.createStatement().executeUpdate("DELETE FROM users WHERE id = " + id) // EXPECT sqli
    }

    @GetMapping("/role")
    fun byRole(@RequestParam role: String) {
        jdbc.queryForList("SELECT * FROM users WHERE role = '" + role + "'") // EXPECT sqli
    }

    // Kotlin string template (idiomatic, not `+`) — still injectable
    @GetMapping("/email")
    fun byEmail(@RequestParam email: String) {
        conn.createStatement().executeQuery("SELECT * FROM users WHERE email = '$email'") // EXPECT sqli
    }
}
