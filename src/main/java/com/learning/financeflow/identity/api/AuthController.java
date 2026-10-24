package com.learning.financeflow.identity.api;
import com.learning.financeflow.identity.service.AuthService;
import jakarta.validation.Valid;
import java.net.URI;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
@RestController @RequestMapping("/api/v1/auth")
public class AuthController {
  private final AuthService service;
  public AuthController(AuthService service){this.service=service;}
  @PostMapping("/register") public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest r){
    UserResponse u=service.register(r); return ResponseEntity.created(URI.create("/api/v1/users/me")).body(u);
  }
  @PostMapping("/login") public AuthResponse login(@Valid @RequestBody LoginRequest r){return service.login(r);}
}
