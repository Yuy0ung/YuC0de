package com.example.sqli;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

@RestController
public class LargeMethodSqli {

    @GetMapping("/unsafe-large")
    public void unsafe(@RequestParam String id) {
        try {
            String sql = "SELECT * FROM users WHERE id = " + id;
            
            // Generate filler lines to exceed 50 lines limit
            int a = 0;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++; // 10
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++; // 20
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++; // 30
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++; // 40
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++; // 50
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++;
            a++; // 60

            Connection conn = DriverManager.getConnection("url", "user", "password");
            Statement stmt = conn.createStatement();
            stmt.executeQuery(sql);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
