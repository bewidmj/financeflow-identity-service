package com.learning.financeflow.identity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.learning.financeflow.identity.user.AppUser;
import com.learning.financeflow.identity.user.AppUserRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class AdminBootstrapTest {

  private final AppUserRepository users = org.mockito.Mockito.mock(AppUserRepository.class);
  private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

  @Test
  void createsAnAdminWithHashedPasswordWhenConfigured() {
    when(users.findByEmail("admin@example.test")).thenReturn(Optional.empty());
    when(users.save(any(AppUser.class))).thenAnswer(call -> call.getArgument(0));
    AdminBootstrap bootstrap = new AdminBootstrap(
        users, encoder, "ADMIN@example.test", "a-long-random-password-123", "Local Admin");

    bootstrap.run(null);

    var captor = org.mockito.ArgumentCaptor.forClass(AppUser.class);
    verify(users).save(captor.capture());
    AppUser created = captor.getValue();
    assertEquals("ADMIN", created.getRole());
    assertEquals("admin@example.test", created.getEmail());
    assertTrue(encoder.matches("a-long-random-password-123", created.getPasswordHash()));
  }

  @Test
  void leavesExistingRegularAccountsUnchanged() {
    AppUser regularUser = new AppUser(
        "admin@example.test", encoder.encode("existing-password"), "Existing User");
    when(users.findByEmail("admin@example.test")).thenReturn(Optional.of(regularUser));
    AdminBootstrap bootstrap = new AdminBootstrap(
        users, encoder, "admin@example.test", "a-long-random-password-123", "Local Admin");

    assertThrows(IllegalStateException.class, () -> bootstrap.run(null));
    verify(users, never()).save(any(AppUser.class));
    assertEquals("USER", regularUser.getRole());
  }

  @Test
  void doesNothingWhenBootstrapIsNotConfigured() {
    AdminBootstrap bootstrap = new AdminBootstrap(users, encoder, "", "", "Local Admin");

    bootstrap.run(null);

    verify(users, never()).findByEmail(any());
  }

  @Test
  void rejectsIncompleteBootstrapConfiguration() {
    AdminBootstrap bootstrap = new AdminBootstrap(
        users, encoder, "admin@example.test", "", "Local Admin");

    assertThrows(IllegalStateException.class, () -> bootstrap.run(null));
  }
}
