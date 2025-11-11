package com.example.bets_service.dto;

import java.math.BigDecimal;
import java.time.Instant;

public record BetResponse(
    Long id,
    Long userId,
    Long matchId,
    Long marketId,
    String selectionCode,
    BigDecimal odds,
    BigDecimal stake,
    BigDecimal potentialReturn,
    String status,
    String result,
    Instant createdAt,
    Instant settledAt
) {}
