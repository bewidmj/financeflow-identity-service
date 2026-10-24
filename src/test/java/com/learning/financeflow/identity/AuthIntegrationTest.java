package com.learning.financeflow.identity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
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
}
