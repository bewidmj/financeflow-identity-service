package com.learning.financeflow.identity.api;
public record AuthResponse(String accessToken, String tokenType, long expiresInSeconds) {}
