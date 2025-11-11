package com.example.bets_service.model;

import java.math.BigDecimal;
import java.time.Instant;

public class Entities {
    public static class Match {
        public Long id;
        public String homeTeam;
        public String awayTeam;
        public Instant startsAt;
        public String status; // SCHEDULED | LIVE | FINISHED
    }
    public static class Market {
        public Long id;
        public Long matchId;
        public String type;
        public java.util.List<Selection> selections;
        public Instant validUntil;
    }
    public static class Selection {
        public String code;
        public String label;
        public BigDecimal odds;
    }
    public static class Bet {
        public Long id;
        public Long userId;
        public Long matchId;
        public Long marketId;
        public String selectionCode;
        public BigDecimal odds;
        public BigDecimal stake;
        public BigDecimal potentialReturn;
        public String status;  // OPEN | SETTLED | CANCELED
        public String result;  // WIN | LOSE | PUSH | CASHOUT | null
        public Instant createdAt;
        public Instant settledAt;
    }
}
