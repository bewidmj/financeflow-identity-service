package com.learning.financeflow.identity.api;

import com.learning.financeflow.identity.service.AdminUserService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/admin")
@SecurityRequirement(name = "bearerAuth")
public class AdminUserController {

  private final AdminUserService service;

  public AdminUserController(AdminUserService service) {
    this.service = service;
  }

  @GetMapping("/overview")
  public AdminOverviewResponse overview() {
    return new AdminOverviewResponse(service.count());
  }

  @GetMapping("/users")
  public Page<UserResponse> searchUsers(
      @RequestParam(required = false) String search,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size) {
    if (page < 0 || size < 1 || size > 100) {
      throw new ResponseStatusException(
          HttpStatus.BAD_REQUEST, "Page must be non-negative and size must be between 1 and 100");
    }
    if (search != null && search.length() > 100) {
      throw new ResponseStatusException(
          HttpStatus.BAD_REQUEST, "Search must be 100 characters or fewer");
    }
    return service.search(
        search,
        PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
  }

  @GetMapping("/users/{id}")
  public UserResponse getUser(@PathVariable UUID id) {
    return service.get(id);
  }

  public record AdminOverviewResponse(long userCount) {}
}
