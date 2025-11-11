package com.example.bets_service.dto;

import java.time.Instant;

public record MarketResponse(
    Long id,
    Long matchId,
    String type,
    java.util.List<MarketSelectionResponse> selections,
    Instant validUntil
) {}
