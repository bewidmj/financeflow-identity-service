package com.learning.financeflow.identity.api;
import com.learning.financeflow.identity.service.AuthService;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
@RestController @RequestMapping("/api/v1/users")
public class UserController {
  private final AuthService service;
  public UserController(AuthService service){this.service=service;}

  @SecurityRequirement(name = "bearerAuth")
  @GetMapping("/me") public UserResponse me(Authentication auth){return service.profile(auth.getName());}
}
