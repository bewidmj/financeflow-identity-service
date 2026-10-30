package com.learning.financeflow.identity.service;

import com.learning.financeflow.identity.user.AppUser;
import com.learning.financeflow.identity.user.AppUserRepository;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@Profile("local")
public class AdminBootstrap implements ApplicationRunner {

  private final AppUserRepository users;
  private final PasswordEncoder passwordEncoder;
  private final String email;
  private final String password;
  private final String displayName;

  public AdminBootstrap(
      AppUserRepository users,
      PasswordEncoder passwordEncoder,
      @Value("${ADMIN_BOOTSTRAP_EMAIL:}") String email,
      @Value("${ADMIN_BOOTSTRAP_PASSWORD:}") String password,
      @Value("${ADMIN_BOOTSTRAP_DISPLAY_NAME:Local administrator}") String displayName) {
    this.users = users;
    this.passwordEncoder = passwordEncoder;
    this.email = email;
    this.password = password;
    this.displayName = displayName;
  }

  @Override
  public void run(ApplicationArguments args) {
    if (email.isBlank() && password.isBlank()) {
      return;
    }
    if (email.isBlank() || password.isBlank()) {
      throw new IllegalStateException(
          "ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD must be configured together");
    }
    if (password.length() < 16
        || password.getBytes(StandardCharsets.UTF_8).length > 72) {
      throw new IllegalStateException(
          "ADMIN_BOOTSTRAP_PASSWORD must be at least 16 characters and at most 72 UTF-8 bytes");
    }

    String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
    var existing = users.findByEmail(normalizedEmail);
    if (existing.isPresent()) {
      if (!"ADMIN".equals(existing.get().getRole())) {
        throw new IllegalStateException(
            "Bootstrap email belongs to a non-admin account; refusing to change its role");
      }
      return;
    }

    users.save(AppUser.admin(
        normalizedEmail,
        passwordEncoder.encode(password),
        displayName.trim()));
  }
}
