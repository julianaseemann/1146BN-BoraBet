package com.example.history_service.config;

import com.example.history_service.model.Entities.BetHistory;
import com.example.history_service.repo.InMemoryStore;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Configuration
public class SampleDataConfig {

    @PostConstruct
    public void init() {
        var store = InMemoryStore.get();

        // Aposta vencida
        var b1 = new BetHistory();
        b1.id = 90001L;
        b1.userId = 42L;
        b1.matchId = 101L;
        b1.matchDescription = "Corinthians x Palmeiras";
        b1.marketType = "1X2";
        b1.selectionLabel = "Corinthians";
        b1.stake = new BigDecimal("50.00");
        b1.odds = new BigDecimal("1.95");
        b1.payout = new BigDecimal("97.50");
        b1.status = "WON";
        b1.placedAt = Instant.now().minus(3, ChronoUnit.DAYS);
        b1.settledAt = Instant.now().minus(2, ChronoUnit.DAYS);
        store.bets.put(b1.id, b1);

        // Aposta perdida
        var b2 = new BetHistory();
        b2.id = 90002L;
        b2.userId = 42L;
        b2.matchId = 102L;
        b2.matchDescription = "Flamengo x Vasco";
        b2.marketType = "1X2";
        b2.selectionLabel = "Flamengo";
        b2.stake = new BigDecimal("30.00");
        b2.odds = new BigDecimal("1.80");
        b2.payout = BigDecimal.ZERO;
        b2.status = "LOST";
        b2.placedAt = Instant.now().minus(1, ChronoUnit.DAYS);
        b2.settledAt = Instant.now().minus(20, ChronoUnit.HOURS);
        store.bets.put(b2.id, b2);

        // Cashout
        var b3 = new BetHistory();
        b3.id = 90003L;
        b3.userId = 42L;
        b3.matchId = 103L;
        b3.matchDescription = "São Paulo x Santos";
        b3.marketType = "1X2";
        b3.selectionLabel = "São Paulo";
        b3.stake = new BigDecimal("100.00");
        b3.odds = new BigDecimal("2.10");
        b3.payout = new BigDecimal("120.00");
        b3.status = "CASHOUT";
        b3.placedAt = Instant.now().minus(6, ChronoUnit.HOURS);
        b3.settledAt = Instant.now().minus(5, ChronoUnit.HOURS);
        store.bets.put(b3.id, b3);
    }
}
