// Injection benchmark fixture — Java SQL injection (VULNERABLE).
// Each trailing marker on a sink line is a bug the taint layer must flag.
// Stack shapes: JDBC Statement, JPA EntityManager, Spring JdbcTemplate.
package com.example.vuln;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class SqliController {
    Connection conn;
    EntityManager em;
    JdbcTemplate jdbc;

    // JDBC Statement with string concatenation
    public void search(HttpServletRequest request) throws SQLException {
        String name = request.getParameter("name");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'"); // EXPECT sqli
    }

    // executeUpdate built from a request param
    @GetMapping("/del")
    public void del(@RequestParam String id) throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.executeUpdate("DELETE FROM users WHERE id = " + id); // EXPECT sqli
    }

    // JPA native query with concatenation
    public void jpa(@RequestParam String email) {
        em.createNativeQuery("SELECT * FROM users WHERE email = '" + email + "'"); // EXPECT sqli
    }

    // Spring JdbcTemplate with concatenation
    public void jdbcQuery(@RequestParam String role) {
        jdbc.queryForList("SELECT * FROM users WHERE role = '" + role + "'"); // EXPECT sqli
    }

    // PreparedStatement built by concatenation is still injectable
    public void prepared(@RequestParam String user) throws SQLException {
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM users WHERE u = '" + user + "'"); // EXPECT sqli
        ps.executeQuery();
    }
}
