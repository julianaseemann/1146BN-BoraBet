package com.example.bets_service.config;

import com.example.bets_service.model.Entities.*;
import com.example.bets_service.repo.InMemoryStore;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Configuration
public class SampleDataConfig {

    @PostConstruct
    public void init() {
        var store = InMemoryStore.get();

        Match m = new Match();
        m.id = 101L;
        m.homeTeam = "Corinthians";
        m.awayTeam = "Palmeiras";
        m.startsAt = Instant.now().plus(2, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
        m.status = "SCHEDULED";
        store.matches.put(m.id, m);

        Market mk = new Market();
        mk.id = 5001L;
        mk.matchId = m.id;
        mk.type = "1X2";
        var s1 = new Selection(); s1.code = "HOME"; s1.label = m.homeTeam; s1.odds = new BigDecimal("1.95");
        var s2 = new Selection(); s2.code = "DRAW"; s2.label = "Empate";   s2.odds = new BigDecimal("3.20");
        var s3 = new Selection(); s3.code = "AWAY"; s3.label = m.awayTeam; s3.odds = new BigDecimal("3.80");
        mk.selections = List.of(s1, s2, s3);
        mk.validUntil = m.startsAt.minus(1, ChronoUnit.MINUTES);
        store.markets.put(mk.id, mk);
    }
}
