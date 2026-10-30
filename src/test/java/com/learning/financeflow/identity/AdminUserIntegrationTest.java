package com.learning.financeflow.identity;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.learning.financeflow.identity.user.AppUser;
import com.learning.financeflow.identity.user.AppUserRepository;
import io.jsonwebtoken.Jwts;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AdminUserIntegrationTest {

  @DynamicPropertySource
  static void configureSigningKey(DynamicPropertyRegistry registry) {
    registry.add("app.jwt.private-key-location", TestRsaKey::privateKeyLocation);
    registry.add("app.jwt.key-id", () -> "identity-test-key");
  }

  @Autowired MockMvc mvc;
  @Autowired AppUserRepository users;
  @Autowired PasswordEncoder passwordEncoder;

  @Test
  void adminCanSearchAndViewSafeUserDetailsButRegularUsersCannot() throws Exception {
    long initialCount = users.count();
    String email = "admin-search-" + UUID.randomUUID() + "@example.test";
    AppUser user = users.save(new AppUser(
        email, passwordEncoder.encode("not-returned-password"), "Searchable Person"));

    mvc.perform(get("/api/v1/admin/overview")
            .header("Authorization", bearer("ADMIN")))
        .andExpect(status().isOk())
        .andExpect(contentTypeJson())
        .andExpect(jsonPath("$.userCount").value(initialCount + 1));

    mvc.perform(get("/api/v1/admin/users")
            .header("Authorization", bearer("ADMIN"))
            .param("search", "searchable person")
            .param("page", "0")
            .param("size", "10"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.totalElements").value(1))
        .andExpect(jsonPath("$.content[0].email").value(email));

    mvc.perform(get("/api/v1/admin/users/{id}", user.getId())
            .header("Authorization", bearer("ADMIN")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.displayName").value("Searchable Person"))
        .andExpect(jsonPath("$.passwordHash").doesNotExist());

    mvc.perform(get("/api/v1/admin/users/{id}", user.getId())
            .header("Authorization", bearer("USER")))
        .andExpect(status().isForbidden());
    mvc.perform(get("/api/v1/admin/overview")
            .header("Authorization", bearer("USER")))
        .andExpect(status().isForbidden());
    mvc.perform(get("/api/v1/admin/users/{id}", UUID.randomUUID())
            .header("Authorization", bearer("ADMIN")))
        .andExpect(status().isNotFound());
    mvc.perform(get("/api/v1/admin/users")
            .header("Authorization", bearer("ADMIN"))
            .param("size", "101"))
        .andExpect(status().isBadRequest());
  }

  private String bearer(String role) {
    Instant now = Instant.now();
    String token = Jwts.builder()
        .header().keyId("identity-test-key").and()
        .subject(UUID.randomUUID().toString())
        .claim("role", role)
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusSeconds(300)))
        .signWith(TestRsaKey.PAIR.getPrivate(), Jwts.SIG.RS256)
        .compact();
    return "Bearer " + token;
  }

  private org.springframework.test.web.servlet.ResultMatcher contentTypeJson() {
    return org.springframework.test.web.servlet.result.MockMvcResultMatchers
        .content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON);
  }
}
