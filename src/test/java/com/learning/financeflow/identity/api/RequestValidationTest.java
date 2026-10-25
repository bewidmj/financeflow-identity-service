package com.learning.financeflow.identity.api;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RequestValidationTest {

    private static Validator validator;
    private static jakarta.validation.ValidatorFactory validatorFactory;

    @BeforeAll
    static void createValidator() {
        validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @AfterAll
    static void closeValidatorFactory() {
        validatorFactory.close();
    }

    @Test
    void registerRequestRejectsMissingOrInvalidEmail() {
        assertTrue(validator.validate(new RegisterRequest(null, "long-password", "Name"))
                .stream().anyMatch(error -> error.getPropertyPath().toString().equals("email")));
        assertTrue(validator.validate(new RegisterRequest("not-an-email", "long-password", "Name"))
                .stream().anyMatch(error -> error.getPropertyPath().toString().equals("email")));
    }

    @Test
    void registerRequestRejectsMissingPasswordAndPasswordOutsideAllowedLength() {
        assertTrue(validator.validate(new RegisterRequest("user@example.com", null, "Name"))
                .stream().anyMatch(error -> error.getPropertyPath().toString().equals("password")));
        assertTrue(validator.validate(new RegisterRequest("user@example.com", "short", "Name"))
                .stream().anyMatch(error -> error.getPropertyPath().toString().equals("password")));
        assertTrue(validator.validate(new RegisterRequest("user@example.com", "x".repeat(73), "Name"))
                .stream().anyMatch(error -> error.getPropertyPath().toString().equals("password")));
    }

    @Test
    void registerRequestAcceptsValidEmailAndPassword() {
        assertTrue(validator.validate(
                new RegisterRequest("user@example.com", "long-password", "Name")).isEmpty());
    }

    @Test
    void registerRequestRejectsMissingBlankAndOverlongDisplayName() {
        assertTrue(validator.validate(new RegisterRequest("user@example.com", "long-password", null))
                .stream().anyMatch(error -> error.getPropertyPath().toString().equals("displayName")));
        assertTrue(validator.validate(new RegisterRequest("user@example.com", "long-password", " "))
                .stream().anyMatch(error -> error.getPropertyPath().toString().equals("displayName")));
        assertTrue(validator.validate(new RegisterRequest("user@example.com", "long-password", "x".repeat(101)))
                .stream().anyMatch(error -> error.getPropertyPath().toString().equals("displayName")));
    }

    @Test
    void loginRequestRequiresValidEmailAndNonblankPassword() {
        var errors = validator.validate(new LoginRequest("", " "));

        assertTrue(errors.stream().anyMatch(error -> error.getPropertyPath().toString().equals("email")));
        assertTrue(errors.stream().anyMatch(error -> error.getPropertyPath().toString().equals("password")));
        assertTrue(validator.validate(new LoginRequest("invalid-email", "password")).stream()
                .anyMatch(error -> error.getPropertyPath().toString().equals("email")));
    }
}
