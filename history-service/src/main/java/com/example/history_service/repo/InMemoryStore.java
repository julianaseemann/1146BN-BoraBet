package com.example.history_service.repo;

import com.example.history_service.model.Entities.BetHistory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryStore {

    public final Map<Long, BetHistory> bets = new ConcurrentHashMap<>();

    private static final InMemoryStore INSTANCE = new InMemoryStore();
    public static InMemoryStore get() { return INSTANCE; }

    private InMemoryStore() {}
}
