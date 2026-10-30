package com.learning.financeflow.identity.service;

import com.learning.financeflow.identity.api.UserResponse;
import com.learning.financeflow.identity.user.AppUser;
import com.learning.financeflow.identity.user.AppUserRepository;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AdminUserService {

  private final AppUserRepository users;

  public AdminUserService(AppUserRepository users) {
    this.users = users;
  }

  @Transactional(readOnly = true)
  public Page<UserResponse> search(String search, Pageable pageable) {
    Page<AppUser> page = search == null || search.isBlank()
        ? users.findAll(pageable)
        : users.findByEmailContainingIgnoreCaseOrDisplayNameContainingIgnoreCase(
            search.trim(), search.trim(), pageable);
    return page.map(this::response);
  }

  @Transactional(readOnly = true)
  public UserResponse get(UUID id) {
    return users.findById(id)
        .map(this::response)
        .orElseThrow(() -> new ResponseStatusException(
            HttpStatus.NOT_FOUND, "User not found"));
  }

  @Transactional(readOnly = true)
  public long count() {
    return users.count();
  }

  private UserResponse response(AppUser user) {
    return new UserResponse(
        user.getId(), user.getEmail(), user.getDisplayName(),
        user.getRole(), user.getCreatedAt());
  }
}
