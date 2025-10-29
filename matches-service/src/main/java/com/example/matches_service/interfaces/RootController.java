package com.example.matches_service.interfaces;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class RootController {
    @GetMapping("/api/matches/_health")
    public Map<String, String> health() {
        return Map.of("service","matches-service","status","OK");
    }
}
