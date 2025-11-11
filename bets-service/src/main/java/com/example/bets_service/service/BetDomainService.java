package com.example.bets_service.service;

import com.example.bets_service.dto.*;
import com.example.bets_service.model.Entities.*;
import com.example.bets_service.repo.InMemoryStore;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

@Service
public class BetDomainService {

    private static final BigDecimal MIN_STAKE = new BigDecimal("1.00");
    private static final BigDecimal MAX_STAKE = new BigDecimal("10000.00");

    public List<MatchResponse> listMatches() {
        return InMemoryStore.get().matches.values().stream()
                .map(m -> new MatchResponse(m.id, m.homeTeam, m.awayTeam, m.startsAt, m.status))
                .sorted((a,b) -> a.startsAt().compareTo(b.startsAt()))
                .toList();
    }

    public List<MarketResponse> listMarkets(Long matchId) {
        return InMemoryStore.get().markets.values().stream()
                .filter(mk -> Objects.equals(mk.matchId, matchId))
                .map(mk -> new MarketResponse(
                        mk.id,
                        mk.matchId,
                        mk.type,
                        mk.selections.stream().map(s -> new MarketSelectionResponse(s.code, s.label, s.odds)).toList(),
                        mk.validUntil
                ))
                .toList();
    }

    public List<BetResponse> listBets(Long userId) {
        return InMemoryStore.get().bets.values().stream()
                .filter(b -> Objects.equals(b.userId, userId))
                .map(this::toResponse)
                .sorted((a,b) -> b.createdAt().compareTo(a.createdAt()))
                .toList();
    }

    public BetResponse getBet(Long userId, Long id) {
        var bet = InMemoryStore.get().bets.get(id);
        if (bet == null || !Objects.equals(bet.userId, userId)) return null;
        return toResponse(bet);
    }

    public BetResponse createBet(Long userId, CreateBetRequest req) {
        if (req.stake().compareTo(MIN_STAKE) < 0 || req.stake().compareTo(MAX_STAKE) > 0) {
            throw new IllegalArgumentException("Stake fora do intervalo permitido");
        }
        var mk = InMemoryStore.get().markets.get(req.marketId());
        if (mk == null || !Objects.equals(mk.matchId, req.matchId())) {
            throw new IllegalArgumentException("Mercado inválido para o jogo informado");
        }
        if (Instant.now().isAfter(mk.validUntil)) {
            throw new IllegalStateException("Mercado fechado");
        }
        var sel = mk.selections.stream().filter(s -> s.code.equals(req.selectionCode())).findFirst().orElse(null);
        if (sel == null) throw new IllegalArgumentException("Seleção inexistente");
        if (sel.odds.subtract(req.expectedOdds()).abs().compareTo(new BigDecimal("0.0001")) > 0) {
            throw new OddsChangedException(sel.odds);
        }

        var id = InMemoryStore.get().betSeq.incrementAndGet();
        var bet = new Bet();
        bet.id = id;
        bet.userId = userId;
        bet.matchId = req.matchId();
        bet.marketId = req.marketId();
        bet.selectionCode = req.selectionCode();
        bet.odds = sel.odds;
        bet.stake = req.stake();
        bet.potentialReturn = sel.odds.multiply(req.stake());
        bet.status = "OPEN";
        bet.result = null;
        bet.createdAt = Instant.now();
        bet.settledAt = null;

        InMemoryStore.get().bets.put(id, bet);
        return toResponse(bet);
    }

    public BetResponse cashout(Long userId, Long id, BigDecimal acceptAmount) {
        var bet = InMemoryStore.get().bets.get(id);
        if (bet == null || !Objects.equals(bet.userId, userId)) return null;
        if (!"OPEN".equals(bet.status)) throw new IllegalStateException("Aposta não está aberta");
        bet.status = "SETTLED";
        bet.result = "CASHOUT";
        bet.settledAt = Instant.now();
        bet.potentialReturn = acceptAmount;
        return toResponse(bet);
    }

    private BetResponse toResponse(Bet b) {
        return new BetResponse(
                b.id, b.userId, b.matchId, b.marketId, b.selectionCode,
                b.odds, b.stake, b.potentialReturn, b.status, b.result, b.createdAt, b.settledAt
        );
    }

    public static class OddsChangedException extends RuntimeException {
        public final BigDecimal currentOdds;
        public OddsChangedException(BigDecimal currentOdds) {
            super("ODDS_CHANGED");
            this.currentOdds = currentOdds;
        }
    }
}
