package com.example.history_service.interfaces;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class RootController {
    @GetMapping("/api/history/_health")
    public Map<String, String> health() {
        return Map.of("service","history-service","status","OK");
    }
}
