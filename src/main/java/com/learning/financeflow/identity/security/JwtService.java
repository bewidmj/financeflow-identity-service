package com.learning.financeflow.identity.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.UnsupportedJwtException;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private final JwtKeyProvider keys;
    private final long expirationMs;

    public JwtService(
            JwtKeyProvider keys,
            @Value("${app.jwt.expiration-ms:3600000}") long expirationMs) {
        this.keys = keys;
        this.expirationMs = expirationMs;
    }

    public String issueToken(UUID id, String email, String role) {
        Instant now = Instant.now();
        return Jwts.builder()
                .header()
                .keyId(keys.activeKeyId())
                .and()
                .subject(id.toString())
                .claim("email", email)
                .claim("role", role)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(expirationMs)))
                .signWith(keys.activePrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    public Claims parseAndValidate(String token) {
        return Jwts.parser()
                .keyLocator(new LocatorAdapter<Key>() {
                    @Override
                    protected Key locate(ProtectedHeader header) {
                        if (!Jwts.SIG.RS256.getId().equals(header.getAlgorithm())) {
                            throw new UnsupportedJwtException("Unsupported JWT algorithm");
                        }
                        Key key = keys.verificationKey(header.getKeyId());
                        if (key == null) {
                            throw new UnsupportedJwtException("Unknown JWT signing key");
                        }
                        return key;
                    }
                })
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public long getExpirationSeconds() {
        return expirationMs / 1000;
    }
}
