package com.example.bets_service.controller;

import com.example.bets_service.dto.*;
import com.example.bets_service.service.BetDomainService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping
public class BetController {

    private final BetDomainService svc;

    public BetController(BetDomainService svc) { this.svc = svc; }

    // --- Matches & Markets (abertos para demo local) ---
    @GetMapping("/matches")
    public List<MatchResponse> matches() { return svc.listMatches(); }

    @GetMapping("/markets")
    public List<MarketResponse> markets(@RequestParam Long matchId) {
        return svc.listMarkets(matchId);
    }

    // MVP: userId fixo (trocar depois para extrair do JWT)
    private Long currentUserId() { return 42L; }

    // --- Bets ---
    @GetMapping("/bets")
    public List<BetResponse> listBets() { return svc.listBets(currentUserId()); }

    @GetMapping("/bets/{id}")
    public ResponseEntity<BetResponse> getBet(@PathVariable Long id) {
        var r = svc.getBet(currentUserId(), id);
        return r == null ? ResponseEntity.status(HttpStatus.NOT_FOUND).build() : ResponseEntity.ok(r);
    }

    @PostMapping("/bets")
    public ResponseEntity<?> create(@Validated @RequestBody CreateBetRequest req) {
        try {
            var r = svc.createBet(currentUserId(), req);
            return ResponseEntity.status(HttpStatus.CREATED).body(r);
        } catch (BetDomainService.OddsChangedException oce) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("error","ODDS_CHANGED","message","As odds mudaram.","details",Map.of("currentOdds", oce.currentOdds)));
        } catch (IllegalArgumentException iae) {
            return ResponseEntity.badRequest().body(Map.of("error","VALIDATION","message", iae.getMessage()));
        } catch (IllegalStateException ise) {
            return ResponseEntity.status(422).body(Map.of("error","CLOSED","message", ise.getMessage()));
        }
    }

    @PostMapping("/bets/{id}/cashout")
    public ResponseEntity<?> cashout(@PathVariable Long id, @Validated @RequestBody CashoutRequest req) {
        try {
            var r = svc.cashout(currentUserId(), id, req.acceptAmount());
            if (r == null) return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            return ResponseEntity.ok(r);
        } catch (IllegalStateException ise) {
            return ResponseEntity.badRequest().body(Map.of("error","INVALID_STATE","message", ise.getMessage()));
        }
    }
}
