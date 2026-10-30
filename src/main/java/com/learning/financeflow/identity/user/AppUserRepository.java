package com.learning.financeflow.identity.user;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
public interface AppUserRepository extends JpaRepository<AppUser, UUID> {
  Optional<AppUser> findByEmail(String email);
  boolean existsByEmail(String email);
  Page<AppUser> findByEmailContainingIgnoreCaseOrDisplayNameContainingIgnoreCase(
      String email, String displayName, Pageable pageable);
}
