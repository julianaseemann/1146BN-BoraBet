package com.example.history_service.service;

import com.example.history_service.dto.BetHistoryResponse;
import com.example.history_service.dto.BetStatus;
import com.example.history_service.model.Entities.BetHistory;
import com.example.history_service.repo.InMemoryStore;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

@Service
public class HistoryDomainService {

    public List<BetHistoryResponse> list(
            Long userId,
            String status,
            Instant from,
            Instant to,
            String match
    ) {
        return InMemoryStore.get().bets.values().stream()
                .filter(b -> Objects.equals(b.userId, userId))
                .filter(b -> filterStatus(b, status))
                .filter(b -> filterFrom(b, from))
                .filter(b -> filterTo(b, to))
                .filter(b -> filterMatch(b, match))
                .sorted(Comparator.comparing((BetHistory b) -> b.placedAt).reversed())
                .map(this::toDto)
                .toList();
    }

    public BetHistoryResponse get(Long userId, Long id) {
        var b = InMemoryStore.get().bets.get(id);
        if (b == null || !Objects.equals(b.userId, userId)) return null;
        return toDto(b);
    }

    private boolean filterStatus(BetHistory b, String status) {
        if (status == null || status.isBlank()) return true;
        return status.equalsIgnoreCase(b.status);
    }

    private boolean filterFrom(BetHistory b, Instant from) {
        return from == null || (b.placedAt != null && !b.placedAt.isBefore(from));
    }

    private boolean filterTo(BetHistory b, Instant to) {
        return to == null || (b.placedAt != null && !b.placedAt.isAfter(to));
    }

    private boolean filterMatch(BetHistory b, String match) {
        if (match == null || match.isBlank()) return true;
        var m = match.toLowerCase(Locale.ROOT);
        return b.matchDescription != null && b.matchDescription.toLowerCase(Locale.ROOT).contains(m);
    }

    private BetHistoryResponse toDto(BetHistory b) {
        BetStatus st;
        try {
            st = BetStatus.valueOf(b.status);
        } catch (Exception e) {
            st = BetStatus.OPEN;
        }
        return new BetHistoryResponse(
                b.id,
                b.userId,
                b.matchId,
                b.matchDescription,
                b.marketType,
                b.selectionLabel,
                b.stake,
                b.odds,
                b.payout,
                st,
                b.placedAt,
                b.settledAt
        );
    }
}
