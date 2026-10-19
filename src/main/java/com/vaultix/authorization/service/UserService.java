package com.vaultix.authorization.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.admin.UserResponse;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Validated
public interface UserService {

    Page<UserResponse> getAllUsers(Pageable pageable);

    UserResponse getUserByIdentifier(
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier);
}
