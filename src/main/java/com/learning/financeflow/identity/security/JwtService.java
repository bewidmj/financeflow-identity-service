package com.learning.financeflow.identity.security;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
@Service
public class JwtService {
  private final SecretKey key; private final long expirationMs;
  public JwtService(@Value("${app.jwt.secret}") String secret, @Value("${app.jwt.expiration-ms:3600000}") long expirationMs) {
    byte[] bytes;
    try { bytes=Decoders.BASE64.decode(secret); } catch(RuntimeException ex) { bytes=secret.getBytes(StandardCharsets.UTF_8); }
    if(bytes.length<32) throw new IllegalArgumentException("app.jwt.secret must provide at least 32 bytes");
    key=Keys.hmacShaKeyFor(bytes); this.expirationMs=expirationMs;
  }
  public String issueToken(UUID id, String email, String role) {
    Instant now=Instant.now();
    return Jwts.builder().subject(id.toString()).claim("email",email).claim("role",role)
      .issuedAt(Date.from(now)).expiration(Date.from(now.plusMillis(expirationMs))).signWith(key).compact();
  }
  public Claims parseAndValidate(String token) { return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload(); }
  public long getExpirationSeconds(){return expirationMs/1000;}
}
