package com.example.sqli;

import org.springframework.web.bind.annotation.*;
import java.sql.*;

@RestController
@RequestMapping("/sqli")
public class CaseTestController {

    @GetMapping("/test")
    public String test(@RequestParam String id, @RequestParam String username, @RequestParam String password) {
        String message = "";
        Connection conn = null;
        Statement stmt = null;
        int rowsAffected = 0;
        String sql = "";
        String type = "update"; // Simulating switch

        try {
            conn = DriverManager.getConnection("url", "user", "pass");
            stmt = conn.createStatement();

            switch (type) {
                case "delete":
                    if (id.equals("admin")) {
                        return "Error";
                    } else {
                        sql = "DELETE FROM sqli WHERE id = '" + id + "'";
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "Deleted" : "Failed";
                        return message;
                    }
                case "update":
                    if (id.equals("admin")) {
                        return "Error";
                    } else {
                        sql = "UPDATE sqli SET password = '" + password + "', username = '" + username + "' WHERE id = '" + id + "'";
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        message = (rowsAffected > 0) ? "Updated" : "Failed";
                        return message;
                    }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return message;
    }
}
