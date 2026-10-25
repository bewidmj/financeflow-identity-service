package com.learning.financeflow.identity.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import static org.junit.jupiter.api.Assertions.*;

class SecurityHandlersTest {

    private ObjectMapper objectMapper;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper().findAndRegisterModules();
        request = new MockHttpServletRequest("GET", "/api/v1/users/me");
    }

    @Test
    void authenticationEntryPointWritesStandardUnauthorizedJson() throws Exception {
        RestAuthenticationEntryPoint entryPoint = new RestAuthenticationEntryPoint(objectMapper);
        MockHttpServletResponse response = new MockHttpServletResponse();

        entryPoint.commence(request, response,
                new InsufficientAuthenticationException("Missing credentials"));

        assertApiError(response, HttpStatus.UNAUTHORIZED,
                "Authentication is required or the token is invalid");
    }

    @Test
    void accessDeniedHandlerWritesStandardForbiddenJson() throws Exception {
        RestAccessDeniedHandler deniedHandler = new RestAccessDeniedHandler(objectMapper);
        MockHttpServletResponse response = new MockHttpServletResponse();

        deniedHandler.handle(request, response, new AccessDeniedException("Forbidden"));

        assertApiError(response, HttpStatus.FORBIDDEN,
                "You do not have permission to access this resource");
    }

    private void assertApiError(
            MockHttpServletResponse response,
            HttpStatus status,
            String message) throws Exception {
        assertEquals(status.value(), response.getStatus());
        assertTrue(MediaType.APPLICATION_JSON.isCompatibleWith(
                MediaType.parseMediaType(response.getContentType())));

        JsonNode body = objectMapper.readTree(response.getContentAsByteArray());
        assertTrue(body.hasNonNull("timestamp"));
        assertTrue(body.get("timestamp").isNumber());
        double timestampSeconds = body.get("timestamp").asDouble();
        double currentTimeSeconds = System.currentTimeMillis() / 1000.0;
        assertTrue(Math.abs(timestampSeconds - currentTimeSeconds) < 5.0);
        assertEquals(status.value(), body.get("status").asInt());
        assertEquals(status.getReasonPhrase(), body.get("error").asText());
        assertEquals(message, body.get("message").asText());
        assertEquals(request.getRequestURI(), body.get("path").asText());
    }
}
