package com.learning.financeflow.identity.service;

import com.learning.financeflow.identity.api.AuthResponse;
import com.learning.financeflow.identity.api.LoginRequest;
import com.learning.financeflow.identity.api.RegisterRequest;
import com.learning.financeflow.identity.api.UserResponse;
import com.learning.financeflow.identity.security.JwtService;
import com.learning.financeflow.identity.user.AppUser;
import com.learning.financeflow.identity.user.AppUserRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AppUserRepository users;

    @Mock
    private PasswordEncoder encoder;

    @Mock
    private JwtService jwt;

    private AuthService service;

    @BeforeEach
    void setUp() {
        service = new AuthService(users, encoder, jwt);
    }

    @Test
    void registerSavesNormalizedEmailAndTrimmedDisplayName() {
        RegisterRequest request =
                new RegisterRequest("  Person@Example.com ", "password123", "  Test Person  ");
        AppUser savedUser = new AppUser("person@example.com", "hashed-password", "Test Person");
        when(users.existsByEmail("person@example.com")).thenReturn(false);
        when(encoder.encode("password123")).thenReturn("hashed-password");
        when(users.saveAndFlush(any(AppUser.class))).thenReturn(savedUser);

        UserResponse response = service.register(request);

        assertEquals("person@example.com", response.email());
        assertEquals("Test Person", response.displayName());
        assertEquals("USER", response.role());
        verify(users).existsByEmail("person@example.com");
        verify(users).saveAndFlush(argThat(user ->
                user.getEmail().equals("person@example.com")
                        && user.getPasswordHash().equals("hashed-password")
                        && user.getDisplayName().equals("Test Person")));
    }

    @Test
    void registerRejectsExistingEmailWithoutEncodingOrSaving() {
        RegisterRequest request = new RegisterRequest("Known@Example.com", "password123", "Person");
        when(users.existsByEmail("known@example.com")).thenReturn(true);

        EmailAlreadyExistsException exception = assertThrows(
                EmailAlreadyExistsException.class,
                () -> service.register(request));

        assertEquals("An account with this email already exists", exception.getMessage());
        verify(users, never()).saveAndFlush(any());
        verifyNoInteractions(encoder, jwt);
    }

    @Test
    void registerStoresBcryptHashInsteadOfPlaintextPassword() {
        PasswordEncoder bcrypt = new BCryptPasswordEncoder();
        AuthService bcryptService = new AuthService(users, bcrypt, jwt);
        RegisterRequest request = new RegisterRequest("bcrypt@example.com", "safe-password-123", "Person");
        when(users.existsByEmail("bcrypt@example.com")).thenReturn(false);
        when(users.saveAndFlush(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        bcryptService.register(request);

        var captor = org.mockito.ArgumentCaptor.forClass(AppUser.class);
        verify(users).saveAndFlush(captor.capture());
        String storedPassword = captor.getValue().getPasswordHash();
        assertNotEquals(request.password(), storedPassword);
        assertTrue(storedPassword.startsWith("$2"));
        assertTrue(bcrypt.matches(request.password(), storedPassword));
    }

    @Test
    void registerTranslatesDatabaseEmailConflictToConflictStatus() {
        RegisterRequest request = new RegisterRequest("conflict@example.com", "password123", "Person");
        when(users.existsByEmail("conflict@example.com")).thenReturn(false);
        when(encoder.encode("password123")).thenReturn("hashed-password");
        when(users.saveAndFlush(any(AppUser.class))).thenThrow(new DataIntegrityViolationException("duplicate"));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> service.register(request));

        assertEquals(HttpStatus.CONFLICT, exception.getStatusCode());
        assertEquals("Email is already registered", exception.getReason());
    }

    @Test
    void loginReturnsBearerTokenAndConfiguredExpiration() {
        UUID userId = UUID.randomUUID();
        AppUser user = mock(AppUser.class);
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("person@example.com");
        when(user.getRole()).thenReturn("USER");
        when(user.getPasswordHash()).thenReturn("hashed-password");
        when(users.findByEmail("person@example.com")).thenReturn(Optional.of(user));
        when(encoder.matches("password123", "hashed-password")).thenReturn(true);
        when(jwt.issueToken(userId, "person@example.com", "USER")).thenReturn("signed.jwt.token");
        when(jwt.getExpirationSeconds()).thenReturn(3600L);

        AuthResponse response = service.login(new LoginRequest(" Person@Example.com ", "password123"));

        assertEquals("signed.jwt.token", response.accessToken());
        assertEquals("Bearer", response.tokenType());
        assertEquals(3600L, response.expiresInSeconds());
        verify(jwt).issueToken(userId, "person@example.com", "USER");
    }

    @Test
    void loginWithUnknownEmailReturnsUnauthorized() {
        when(users.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> service.login(new LoginRequest("Missing@Example.com", "password123")));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
        assertEquals("Invalid email or password", exception.getReason());
        verifyNoInteractions(encoder, jwt);
    }

    @Test
    void loginWithIncorrectPasswordReturnsUnauthorized() {
        AppUser user = new AppUser("person@example.com", "hashed-password", "Person");
        when(users.findByEmail("person@example.com")).thenReturn(Optional.of(user));
        when(encoder.matches("wrong-password", "hashed-password")).thenReturn(false);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> service.login(new LoginRequest("person@example.com", "wrong-password")));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
        assertEquals("Invalid email or password", exception.getReason());
        verifyNoInteractions(jwt);
    }

    @Test
    void profileRejectsMalformedSubjectAsUnauthorized() {
        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> service.profile("not-a-uuid"));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
        assertEquals("Invalid token subject", exception.getReason());
        verifyNoInteractions(users, encoder, jwt);
    }

    @Test
    void profileRejectsUserThatNoLongerExists() {
        UUID id = UUID.randomUUID();
        when(users.findById(id)).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> service.profile(id.toString()));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
        assertEquals("User no longer exists", exception.getReason());
    }
}
