package com.learning.financeflow.identity.user;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;
@Entity
@Table(name="identity_users", uniqueConstraints=@UniqueConstraint(name="uk_identity_users_email", columnNames="email"))
public class AppUser {
  @Id @GeneratedValue(strategy=GenerationType.UUID) private UUID id;
  @Column(nullable=false, length=320) private String email;
  @Column(name="password_hash", nullable=false, length=100) private String passwordHash;
  @Column(name="display_name", nullable=false, length=100) private String displayName;
  @Column(nullable=false, length=30) private String role="USER";
  @Column(name="created_at", nullable=false, updatable=false) private Instant createdAt;
  protected AppUser() {}
  public AppUser(String email, String passwordHash, String displayName) {
    this.email=email; this.passwordHash=passwordHash; this.displayName=displayName; this.role="USER";
  }
  @PrePersist void onCreate() { if (createdAt==null) createdAt=Instant.now(); }
  public UUID getId(){return id;} public String getEmail(){return email;}
  public String getPasswordHash(){return passwordHash;} public String getDisplayName(){return displayName;}
  public String getRole(){return role;} public Instant getCreatedAt(){return createdAt;}
}
