package com.learning.financeflow.identity.api;
import jakarta.validation.constraints.*;
public record RegisterRequest(
 @NotBlank @Email @Size(max=320) String email,
 @NotBlank @Size(min=10,max=72,message="password must be between 10 and 72 characters") String password,
 @NotBlank @Size(max=100) String displayName) {}
