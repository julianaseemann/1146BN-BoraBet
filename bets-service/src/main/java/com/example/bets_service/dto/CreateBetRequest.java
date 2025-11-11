package com.example.bets_service.dto;

import java.math.BigDecimal;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record CreateBetRequest(
    @NotNull Long matchId,
    @NotNull Long marketId,
    @NotNull @Size(min = 1, max = 30) String selectionCode,
    @NotNull @Min(1) BigDecimal stake,
    @NotNull BigDecimal expectedOdds,
    @Size(max = 64) String idempotencyKey
) {}
