package com.learning.financeflow.identity.security;

import io.jsonwebtoken.JwtException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private static final String SIGNING_KEY = encodeKey("unit-test-only-signing-key-which-is-long-enough");
    private static final String OTHER_SIGNING_KEY = encodeKey("different-test-only-signing-key-long-enough");

    @Test
    void issuedTokenContainsExpectedIdentityClaimsAndCanBeValidated() {
        JwtService jwt = new JwtService(SIGNING_KEY, 3_600_000);
        UUID userId = UUID.randomUUID();

        String token = jwt.issueToken(userId, "user@example.test", "USER");
        var claims = jwt.parseAndValidate(token);

        assertEquals(userId.toString(), claims.getSubject());
        assertEquals("user@example.test", claims.get("email", String.class));
        assertEquals("USER", claims.get("role", String.class));
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpiration());
        assertEquals(3600L, jwt.getExpirationSeconds());
    }

    @Test
    void tokenSignedWithDifferentKeyIsRejected() {
        JwtService issuer = new JwtService(SIGNING_KEY, 3_600_000);
        JwtService verifier = new JwtService(OTHER_SIGNING_KEY, 3_600_000);
        String token = issuer.issueToken(UUID.randomUUID(), "user@example.test", "USER");

        assertThrows(JwtException.class, () -> verifier.parseAndValidate(token));
    }

    @Test
    void expiredTokenIsRejected() {
        JwtService jwt = new JwtService(SIGNING_KEY, -1_000);
        String token = jwt.issueToken(UUID.randomUUID(), "user@example.test", "USER");

        assertThrows(JwtException.class, () -> jwt.parseAndValidate(token));
    }

    @Test
    void malformedTokenIsRejected() {
        JwtService jwt = new JwtService(SIGNING_KEY, 3_600_000);

        assertThrows(JwtException.class, () -> jwt.parseAndValidate("not-a-jwt"));
    }

    private static String encodeKey(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
