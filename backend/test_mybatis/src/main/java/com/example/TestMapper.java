package com.example;
import java.util.List;
import org.apache.ibatis.annotations.Param;

public interface TestMapper {
    List<Object> queryAll(@Param("name") String name);
}
