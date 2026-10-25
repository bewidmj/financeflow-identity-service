package com.learning.financeflow.identity.api;

import com.learning.financeflow.identity.service.EmailAlreadyExistsException;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.*;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler handler;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        handler = new GlobalExceptionHandler();
        request = new MockHttpServletRequest("POST", "/api/v1/auth/register");
    }

    @Test
    void validationErrorReturnsBadRequestWithFieldMessage() throws Exception {
        BeanPropertyBindingResult bindingResult =
                new BeanPropertyBindingResult(new RegisterRequest("", "", ""), "registerRequest");
        bindingResult.addError(new FieldError("registerRequest", "email", "", false,
                new String[]{"NotBlank.registerRequest.email"}, null, "must not be blank"));
        bindingResult.addError(new FieldError("registerRequest", "password", "", false,
                new String[]{"NotBlank.registerRequest.password"}, null, "must not be blank"));
        MethodArgumentNotValidException exception = new MethodArgumentNotValidException(
                new MethodParameter(ValidationFixture.class.getDeclaredMethod("validate", RegisterRequest.class), 0),
                bindingResult);

        var response = handler.handleValidation(exception, request);

        assertError(response.getBody(), HttpStatus.BAD_REQUEST, "email: must not be blank; password: must not be blank");
    }

    @Test
    void malformedJsonReturnsBadRequest() {
        var response = handler.handleInvalidJson(
                new HttpMessageNotReadableException("bad json"), request);

        assertError(response.getBody(), HttpStatus.BAD_REQUEST, "Invalid or malformed JSON request");
    }

    @Test
    void dataIntegrityViolationReturnsConflict() {
        var response = handler.handleDataIntegrity(
                new DataIntegrityViolationException("constraint"), request);

        assertError(response.getBody(), HttpStatus.CONFLICT, "The request conflicts with existing data");
    }

    @Test
    void responseStatusExceptionPreservesStatusAndReason() {
        var response = handler.handleResponseStatus(
                new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"), request);

        assertError(response.getBody(), HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }

    @Test
    void responseStatusExceptionWithoutReasonUsesStatusPhrase() {
        var response = handler.handleResponseStatus(
                new ResponseStatusException(HttpStatus.NOT_FOUND), request);

        assertError(response.getBody(), HttpStatus.NOT_FOUND, "Not Found");
    }

    @Test
    void unexpectedExceptionReturnsGenericInternalServerError() {
        var response = handler.handleUnexpected(new IllegalStateException("internal details"), request);

        assertError(response.getBody(), HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred");
    }

    @Test
    void duplicateEmailReturnsConflictWithExceptionMessage() {
        var response = handler.handleEmailAlreadyExists(
                new EmailAlreadyExistsException("Email already exists"), request);

        assertError(response.getBody(), HttpStatus.CONFLICT, "Email already exists");
    }

    private void assertError(ApiErrorResponse body, HttpStatus status, String message) {
        assertNotNull(body);
        assertEquals(status.value(), body.status());
        assertEquals(status.getReasonPhrase(), body.error());
        assertEquals(message, body.message());
        assertEquals(request.getRequestURI(), body.path());
        assertNotNull(body.timestamp());
        assertFalse(body.timestamp().isAfter(Instant.now()));
    }

    private static class ValidationFixture {
        @SuppressWarnings("unused")
        void validate(RegisterRequest request) {
        }
    }
}
