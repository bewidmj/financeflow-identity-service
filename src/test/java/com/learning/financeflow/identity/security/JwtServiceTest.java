package com.learning.financeflow.identity.security;

import com.learning.financeflow.identity.TestRsaKey;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private static final String KEY_ID = "identity-test-key";

    @Test
    void issuedTokenContainsExpectedClaimsAndRs256KeyId() {
        JwtService jwt = service(TestRsaKey.PAIR, KEY_ID, 3_600_000);
        UUID userId = UUID.randomUUID();
        Instant beforeIssue = Instant.now();

        String token = jwt.issueToken(userId, "user@example.test", "USER");
        var parsed = Jwts.parser()
                .verifyWith(TestRsaKey.PAIR.getPublic())
                .build()
                .parseSignedClaims(token);

        assertEquals("RS256", parsed.getHeader().getAlgorithm());
        assertEquals(KEY_ID, parsed.getHeader().getKeyId());
        assertEquals(userId.toString(), parsed.getPayload().getSubject());
        assertEquals("user@example.test",
                parsed.getPayload().get("email", String.class));
        assertEquals("USER", parsed.getPayload().get("role", String.class));
        assertNotNull(parsed.getPayload().getIssuedAt());
        assertNotNull(parsed.getPayload().getExpiration());
        assertTrue(parsed.getPayload().getIssuedAt().getTime()
                >= beforeIssue.toEpochMilli() - 1_000);
        assertEquals(3_600_000,
                parsed.getPayload().getExpiration().getTime()
                        - parsed.getPayload().getIssuedAt().getTime());
        assertEquals(3600L, jwt.getExpirationSeconds());
        assertEquals(userId.toString(), jwt.parseAndValidate(token).getSubject());
    }

    @Test
    void tokenSignedByUnrelatedPrivateKeyIsRejected() {
        JwtService trusted = service(TestRsaKey.PAIR, KEY_ID, 3_600_000);
        JwtService unrelated = service(
                TestRsaKey.generateKeyPair(), KEY_ID, 3_600_000);

        assertThrows(JwtException.class, () -> trusted.parseAndValidate(
                unrelated.issueToken(
                        UUID.randomUUID(), "user@example.test", "USER")));
    }

    @Test
    void expiredTokenIsRejected() {
        JwtService jwt = service(TestRsaKey.PAIR, KEY_ID, -1_000);

        assertThrows(JwtException.class, () -> jwt.parseAndValidate(
                jwt.issueToken(
                        UUID.randomUUID(), "user@example.test", "USER")));
    }

    @Test
    void malformedTokenIsRejected() {
        JwtService jwt = service(TestRsaKey.PAIR, KEY_ID, 3_600_000);

        assertThrows(JwtException.class,
                () -> jwt.parseAndValidate("not-a-jwt"));
    }

    @Test
    void unknownKeyIdIsRejected() {
        JwtService jwt = service(TestRsaKey.PAIR, KEY_ID, 3_600_000);
        Instant now = Instant.now();
        String token = Jwts.builder()
                .header()
                .keyId("unknown-key")
                .and()
                .subject(UUID.randomUUID().toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(300)))
                .signWith(TestRsaKey.PAIR.getPrivate(), Jwts.SIG.RS256)
                .compact();

        assertThrows(JwtException.class, () -> jwt.parseAndValidate(token));
    }

    @Test
    void additionalPublicKeyCanValidateTokensDuringRotation() {
        KeyPair previousPair = TestRsaKey.generateKeyPair();
        JwtKeyProvider provider = new JwtKeyProvider(
                new DefaultResourceLoader(),
                TestRsaKey.writePrivateKey(TestRsaKey.PAIR),
                KEY_ID,
                "previous-key=" + TestRsaKey.writePublicKey(previousPair));
        JwtService jwt = new JwtService(provider, 3_600_000);
        Instant now = Instant.now();
        String previousToken = Jwts.builder()
                .header()
                .keyId("previous-key")
                .and()
                .subject(UUID.randomUUID().toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(300)))
                .signWith(previousPair.getPrivate(), Jwts.SIG.RS256)
                .compact();

        assertEquals(2, provider.jwkSet().size());
        assertTrue(provider.jwkSet().stream()
                .anyMatch(jwk -> "previous-key".equals(jwk.get("kid"))));
        assertNotNull(jwt.parseAndValidate(previousToken));
    }

    @Test
    void missingOrInvalidPrivateKeyConfigurationFailsClearly() throws Exception {
        var resources = new DefaultResourceLoader();
        assertThrows(IllegalStateException.class, () -> new JwtKeyProvider(
                resources, "", KEY_ID, ""));
        assertThrows(IllegalStateException.class, () -> new JwtKeyProvider(
                resources, "classpath:application-test.yml", KEY_ID, ""));

        var invalidPem = java.nio.file.Files.createTempFile(
                "financeflow-invalid-jwt-", ".pem");
        invalidPem.toFile().deleteOnExit();
        java.nio.file.Files.writeString(invalidPem, "not a PEM key");
        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> new JwtKeyProvider(
                        resources, invalidPem.toUri().toString(), KEY_ID, ""));
        assertTrue(exception.getMessage().contains("PRIVATE KEY"));
    }

    private static JwtService service(KeyPair pair, String keyId, long expirationMs) {
        JwtKeyProvider provider = new JwtKeyProvider(
                new DefaultResourceLoader(),
                TestRsaKey.writePrivateKey(pair),
                keyId,
                "");
        return new JwtService(provider, expirationMs);
    }
}
