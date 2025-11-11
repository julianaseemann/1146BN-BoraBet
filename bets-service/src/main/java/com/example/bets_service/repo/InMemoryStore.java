package com.example.bets_service.repo;

import com.example.bets_service.model.Entities.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class InMemoryStore {
    public final Map<Long, Match> matches = new ConcurrentHashMap<>();
    public final Map<Long, Market> markets = new ConcurrentHashMap<>();
    public final Map<Long, Bet> bets = new ConcurrentHashMap<>();

    public final AtomicLong betSeq = new AtomicLong(90000);

    private static final InMemoryStore INSTANCE = new InMemoryStore();
    public static InMemoryStore get() { return INSTANCE; }

    private InMemoryStore() {}
}
