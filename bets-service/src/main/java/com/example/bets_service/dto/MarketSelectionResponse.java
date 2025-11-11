package com.example.bets_service.dto;

import java.math.BigDecimal;

public record MarketSelectionResponse(
    String code,
    String label,
    BigDecimal odds
) {}
