package com.example.bets_service.interfaces;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class RootController {
    @GetMapping("/api/bets/_health")
    public Map<String, String> health() {
        return Map.of("service","bets-service","status","OK");
    }
}
