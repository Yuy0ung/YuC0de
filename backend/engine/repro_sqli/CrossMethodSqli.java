package com.example.sqli;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class CrossMethodSqli {
    public void unsafe(String id) {
        try {
            Connection conn = DriverManager.getConnection("url", "user", "password");
            Statement stmt = conn.createStatement();
            stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
