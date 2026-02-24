package com.example;
import java.util.List;

public class TestController {
    TestMapper mapper;

    // Case 1: Void return, simple parameter
    public void method1(String name) {
        mapper.queryAll(name);
    }

    // Case 2: Return statement, simple parameter
    public List<Object> method2(String name) {
        return mapper.queryAll(name);
    }

    // Case 3: Local variable alias
    public void method3(String name) {
        String n = name;
        mapper.queryAll(n);
    }

    // Case 4: Multi-line parameter with annotation
    public void method4(
        @RequestParam(value="name") String name
    ) {
        mapper.queryAll(name);
    }
}
