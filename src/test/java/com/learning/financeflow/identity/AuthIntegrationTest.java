package com.learning.financeflow.identity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.learning.financeflow.identity.security.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import java.util.UUID;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@SpringBootTest @AutoConfigureMockMvc @ActiveProfiles("test")
class AuthIntegrationTest {
  @Autowired MockMvc mvc; @Autowired ObjectMapper mapper;
  @Test void registerLoginAndReadOwnProfile() throws Exception {
    String email="user-"+java.util.UUID.randomUUID()+"@example.com";
    String body="{\"email\":\""+email+"\",\"password\":\"ChangeMe123!\",\"displayName\":\"Test User\"}";
    mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content(body))
      .andExpect(status().isCreated()).andExpect(jsonPath("$.email").value(email));
    String result=mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
      .content("{\"email\":\""+email+"\",\"password\":\"ChangeMe123!\"}"))
      .andExpect(status().isOk()).andExpect(jsonPath("$.accessToken").isNotEmpty()).andReturn().getResponse().getContentAsString();
    JsonNode json=mapper.readTree(result); String token=json.get("accessToken").asText();
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
    String otherTestOnlySecret = java.util.Base64.getEncoder().encodeToString(
      "different-integration-test-key-which-is-long-enough".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    String invalidToken = new JwtService(otherTestOnlySecret, 3600000)
      .issueToken(UUID.randomUUID(), "attacker@example.test", "USER");

    mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + invalidToken))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.status").value(401))
      .andExpect(jsonPath("$.path").value("/api/v1/users/me"))
      .andExpect(jsonPath("$.message").value("Authentication is required or the token is invalid"));
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
