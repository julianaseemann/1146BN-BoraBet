package com.example.gateway_service.infrastructure.config;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import reactor.core.publisher.Mono;

public class AuthorizationFilter implements WebFilter {

    @Value("${jwt.secret}")
    private String jwtSecret;

    // Rotas públicas do Gateway
    private static final List<String> PUBLIC_ROUTES = List.of(
        "/auth-service/auth",          // login
        "/auth-service/users",         // cadastro
        "/matches-service/matches", 
        "/tournaments-service/tournaments"
    );

    private boolean isPublicRoute(String path) {
        return PUBLIC_ROUTES.stream().anyMatch(path::startsWith);
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().toString();
        String method = request.getMethod().name();

        // 1) OS BROWSERS SEMPRE ENVIAM OPTIONS → LIBERAR TOTALMENTE
        if (method.equalsIgnoreCase("OPTIONS")) {
            exchange.getResponse().setStatusCode(HttpStatus.OK);
            return exchange.getResponse().setComplete();
        }

        // 2) Rotas públicas
        if (isPublicRoute(path)) {
            return chain.filter(exchange);
        }

        // 3) Exigir token nas demais rotas
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return unauthorized(exchange);
        }

        String token = authHeader.substring(7);

        try {
            Algorithm algorithm = Algorithm.HMAC256(jwtSecret.getBytes(StandardCharsets.UTF_8));
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT jwt = verifier.verify(token);

            // Verificar tipo do token
            if (!"access".equals(jwt.getClaim("type").asString())) {
                return unauthorized(exchange);
            }

        } catch (Exception e) {
            return unauthorized(exchange);
        }

        return chain.filter(exchange);
    }
}
