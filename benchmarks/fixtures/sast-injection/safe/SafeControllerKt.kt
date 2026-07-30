// Injection benchmark fixture — Kotlin/Spring SAFE / benign near-misses.
// NOTHING here may be flagged — the false-positive side for Kotlin.
package com.example.safe

import java.io.File
import java.sql.Connection
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.RequestParam

class SafeControllerKt(val conn: Connection, val jdbc: JdbcTemplate) {

    // SAFE: PreparedStatement with a bind parameter
    fun search(@RequestParam name: String) {
        val ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?")
        ps.setString(1, name)
        ps.executeQuery()
    }

    // SAFE: JdbcTemplate parameterized (? + args)
    fun byRole(@RequestParam role: String) {
        jdbc.queryForList("SELECT * FROM users WHERE role = ?", role)
    }

    // SAFE: constant SQL, no user input
    fun all() {
        conn.createStatement().executeQuery("SELECT * FROM users")
    }

    // SAFE: constant-path file read
    fun config() {
        File("/etc/app/config.yaml").readText()
    }
}
