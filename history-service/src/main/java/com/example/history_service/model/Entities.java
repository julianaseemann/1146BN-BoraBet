package com.example.history_service.model;

import java.math.BigDecimal;
import java.time.Instant;

public class Entities {

    public static class BetHistory {
        public Long id;
        public Long userId;
        public Long matchId;
        public String matchDescription;  // "Corinthians x Palmeiras"
        public String marketType;        // "1X2"
        public String selectionLabel;    // "Corinthians"
        public BigDecimal stake;
        public BigDecimal odds;
        public BigDecimal payout;        // quanto recebeu de fato
        public String status;            // OPEN | WON | LOST | CASHOUT | CANCELED
        public Instant placedAt;
        public Instant settledAt;
    }
}
