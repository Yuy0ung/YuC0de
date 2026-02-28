package com.example.sqli;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CrossMethodCaller {
    @GetMapping("/call")
    public void entry(@RequestParam String input) {
        new CrossMethodSqli().unsafe(input);
    }
}
