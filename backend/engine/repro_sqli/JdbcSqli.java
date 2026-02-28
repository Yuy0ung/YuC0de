package com.example.sqli;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JdbcSqli {

    @GetMapping("/unsafe")
    public void unsafe(@RequestParam String id) {
        try {
            Connection conn = DriverManager.getConnection("url", "user", "password");
            Statement stmt = conn.createStatement();
            String sql = "SELECT * FROM users WHERE id = " + id;
            stmt.executeQuery(sql);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
