package com.example.history_service.dto;

import java.math.BigDecimal;
import java.time.Instant;

public record BetHistoryResponse(
        Long id,
        Long userId,
        Long matchId,
        String matchDescription,
        String marketType,
        String selectionLabel,
        BigDecimal stake,
        BigDecimal odds,
        BigDecimal payout,
        BetStatus status,
        Instant placedAt,
        Instant settledAt
) {}
