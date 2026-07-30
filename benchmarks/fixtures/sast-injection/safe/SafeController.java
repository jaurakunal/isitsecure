// Injection benchmark fixture — Java SAFE / benign near-misses.
// NOTHING here may be flagged — this is the false-positive side for Java.
package com.example.safe;

import java.io.File;
import java.io.FileInputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.RequestParam;

public class SafeController {
    Connection conn;
    JdbcTemplate jdbc;

    // SAFE: PreparedStatement with a bind parameter (not string-built)
    public void search(HttpServletRequest request) throws SQLException {
        String name = request.getParameter("name");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ps.executeQuery();
    }

    // SAFE: JdbcTemplate with a ? placeholder + args (parameterized)
    public void byRole(@RequestParam String role) {
        jdbc.queryForList("SELECT * FROM users WHERE role = ?", role);
    }

    // SAFE: a constant SQL string (no user input)
    public void all() throws SQLException {
        conn.createStatement().executeQuery("SELECT * FROM users");
    }

    // SAFE: constant-path file read (not user-derived)
    public void config() throws Exception {
        new FileInputStream(new File("/etc/app/config.yaml"));
    }
}
