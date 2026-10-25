package com.learning.financeflow.identity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.learning.financeflow.identity.TestRsaKey;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@SpringBootTest @AutoConfigureMockMvc @ActiveProfiles("test")
class AuthIntegrationTest {
  @Autowired MockMvc mvc; @Autowired ObjectMapper mapper;
  @DynamicPropertySource
  static void configureTestSigningKey(DynamicPropertyRegistry registry) {
    registry.add("app.jwt.private-key-location", TestRsaKey::privateKeyLocation);
    registry.add("app.jwt.key-id", () -> "identity-test-key");
  }

  @Test void registerLoginAndReadOwnProfile() throws Exception {
    String email="user-"+java.util.UUID.randomUUID()+"@example.com";
    String body="{\"email\":\""+email+"\",\"password\":\"ChangeMe123!\",\"displayName\":\"Test User\"}";
    String registration = mvc.perform(post("/api/v1/auth/register")
        .contentType(MediaType.APPLICATION_JSON).content(body))
      .andExpect(status().isCreated())
      .andExpect(jsonPath("$.email").value(email))
      .andReturn().getResponse().getContentAsString();
    String registeredId = mapper.readTree(registration).get("id").asText();
    String result=mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
      .content("{\"email\":\""+email+"\",\"password\":\"ChangeMe123!\"}"))
      .andExpect(status().isOk()).andExpect(jsonPath("$.accessToken").isNotEmpty()).andReturn().getResponse().getContentAsString();
    JsonNode json=mapper.readTree(result); String token=json.get("accessToken").asText();
    var parsed = Jwts.parser().verifyWith(TestRsaKey.PAIR.getPublic())
      .build().parseSignedClaims(token);
    assertEquals("RS256", parsed.getHeader().getAlgorithm());
    assertEquals("identity-test-key", parsed.getHeader().getKeyId());
    assertEquals(registeredId, parsed.getPayload().getSubject());
    assertEquals(email, parsed.getPayload().get("email", String.class));
    assertEquals("USER", parsed.getPayload().get("role", String.class));
    assertEquals(3600, (parsed.getPayload().getExpiration().getTime()
      - parsed.getPayload().getIssuedAt().getTime()) / 1000);
    mvc.perform(get("/api/v1/users/me").header("Authorization","Bearer "+token))
      .andExpect(status().isOk()).andExpect(jsonPath("$.email").value(email)).andExpect(jsonPath("$.displayName").value("Test User"));
  }
  @Test void duplicateEmailIsRejected() throws Exception {
    String email="duplicate-"+java.util.UUID.randomUUID()+"@example.com";
    String body="{\"email\":\""+email+"\",\"password\":\"ChangeMe123!\",\"displayName\":\"Test User\"}";
    mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isCreated());
    mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isConflict());
  }
  @Test void profileRequiresAuthentication() throws Exception {
    mvc.perform(get("/api/v1/users/me")).andExpect(status().isUnauthorized());
  }

  @Test void healthEndpointIsPublic() throws Exception {
    mvc.perform(get("/actuator/health"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status").value("UP"));
  }

  @Test void protectedEndpointRejectsAuthorizationHeaderWithoutBearerScheme() throws Exception {
    mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer not-a-valid-jwt"))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.status").value(401))
      .andExpect(jsonPath("$.path").value("/api/v1/users/me"));
  }

  @Test void protectedEndpointRejectsJwtWithInvalidSignature() throws Exception {
    KeyPair otherPair = TestRsaKey.generateKeyPair();
    Instant now = Instant.now();
    String invalidToken = Jwts.builder().header().keyId("identity-test-key").and()
      .subject(UUID.randomUUID().toString())
      .claim("email", "attacker@example.test")
      .claim("role", "USER")
      .issuedAt(Date.from(now))
      .expiration(Date.from(now.plusSeconds(3600)))
      .signWith(otherPair.getPrivate(), Jwts.SIG.RS256)
      .compact();

    mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + invalidToken))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.status").value(401))
      .andExpect(jsonPath("$.path").value("/api/v1/users/me"))
      .andExpect(jsonPath("$.message").value("Authentication is required or the token is invalid"));
  }

  @Test void jwksEndpointPublishesOnlyTheActivePublicKey() throws Exception {
    JsonNode jwks = mapper.readTree(mvc.perform(get("/.well-known/jwks.json"))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andReturn().getResponse().getContentAsByteArray());
    JsonNode key = jwks.get("keys").get(0);
    assertEquals(1, jwks.get("keys").size());
    assertEquals("RSA", key.get("kty").asText());
    assertEquals("sig", key.get("use").asText());
    assertEquals("RS256", key.get("alg").asText());
    assertEquals("identity-test-key", key.get("kid").asText());
    var publicKey = (java.security.interfaces.RSAPublicKey) TestRsaKey.PAIR.getPublic();
    assertEquals(base64UrlUnsigned(publicKey.getModulus()), key.get("n").asText());
    assertEquals(base64UrlUnsigned(publicKey.getPublicExponent()), key.get("e").asText());
    for (String privateParameter : new String[] {
        "d", "p", "q", "dp", "dq", "qi"}) {
      org.junit.jupiter.api.Assertions.assertFalse(key.has(privateParameter));
    }
  }

  private String base64UrlUnsigned(java.math.BigInteger value) {
    byte[] bytes = value.toByteArray();
    int offset = bytes.length > 1 && bytes[0] == 0 ? 1 : 0;
    return Base64.getUrlEncoder().withoutPadding()
      .encodeToString(java.util.Arrays.copyOfRange(bytes, offset, bytes.length));
  }

  @Test void authenticationEndpointsArePublicAndValidateMalformedBodies() throws Exception {
    mvc.perform(post("/api/v1/auth/register")
        .contentType(MediaType.APPLICATION_JSON)
        .content("{"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.message").value("Invalid or malformed JSON request"));

    mvc.perform(post("/api/v1/auth/login")
        .contentType(MediaType.APPLICATION_JSON)
        .content(""))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.message").value("Invalid or malformed JSON request"));
  }

  @Test void registrationRejectsInvalidRequestFields() throws Exception {
    mvc.perform(post("/api/v1/auth/register")
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"email\":\"invalid\",\"password\":\"short\",\"displayName\":\"Test\"}"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.status").value(400))
      .andExpect(jsonPath("$.path").value("/api/v1/auth/register"))
      .andExpect(jsonPath("$.message").isNotEmpty());
  }
}
