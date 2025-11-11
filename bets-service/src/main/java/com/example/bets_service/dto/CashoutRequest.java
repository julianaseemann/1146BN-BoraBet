package com.example.bets_service.dto;

import java.math.BigDecimal;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

public record CashoutRequest(
    @NotNull @Min(0) BigDecimal acceptAmount
) {}
