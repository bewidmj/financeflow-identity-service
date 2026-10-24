package com.learning.financeflow.identity.service;
import com.learning.financeflow.identity.api.*;
import com.learning.financeflow.identity.security.JwtService;
import com.learning.financeflow.identity.user.*;
import java.util.Locale;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
@Service
public class AuthService {
  private final AppUserRepository users; private final PasswordEncoder encoder; private final JwtService jwt;
  public AuthService(AppUserRepository users,PasswordEncoder encoder,JwtService jwt){this.users=users;this.encoder=encoder;this.jwt=jwt;}
  @Transactional public UserResponse register(RegisterRequest r) {
    String email=norm(r.email());
    if(users.existsByEmail(email)) throw new ResponseStatusException(HttpStatus.CONFLICT,"Email is already registered");
    try { return response(users.saveAndFlush(new AppUser(email,encoder.encode(r.password()),r.displayName().trim()))); }
    catch(DataIntegrityViolationException ex){throw new ResponseStatusException(HttpStatus.CONFLICT,"Email is already registered");}
  }
  @Transactional(readOnly=true) public AuthResponse login(LoginRequest r) {
    AppUser user=users.findByEmail(norm(r.email())).orElseThrow(()->new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Invalid email or password"));
    if(!encoder.matches(r.password(),user.getPasswordHash())) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Invalid email or password");
    return new AuthResponse(jwt.issueToken(user.getId(),user.getEmail(),user.getRole()),"Bearer",jwt.getExpirationSeconds());
  }
  @Transactional(readOnly=true) public UserResponse profile(String subject) {
    UUID id;
    try{id=UUID.fromString(subject);}catch(IllegalArgumentException ex){throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Invalid token subject");}
    return users.findById(id).map(this::response).orElseThrow(()->new ResponseStatusException(HttpStatus.UNAUTHORIZED,"User no longer exists"));
  }
  private UserResponse response(AppUser u){return new UserResponse(u.getId(),u.getEmail(),u.getDisplayName(),u.getRole(),u.getCreatedAt());}
  private String norm(String email){return email.trim().toLowerCase(Locale.ROOT);}
}
