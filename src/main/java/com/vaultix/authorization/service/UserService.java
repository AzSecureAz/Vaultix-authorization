package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.admin.CreateUserRequest;
import com.vaultix.authorization.dto.admin.UpdateUserRequest;
import com.vaultix.authorization.dto.admin.UserResponse;
import com.vaultix.authorization.specification.request.UserSearchRequest;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Validated
public interface UserService {

    Page<UserResponse> getAllUsers(Pageable pageable);

    Page<UserResponse> searchUsers(@Valid UserSearchRequest request, Pageable pageable);

    UserResponse getUserByIdentifier(
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier);

    UserResponse createUser(
            @NotNull(message = "Create user request cannot be null")
            @Valid CreateUserRequest request,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);

    UserResponse updateUser(
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @NotNull(message = "Update user request cannot be null")
            @Valid UpdateUserRequest request,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);

    UserResponse disableUser(
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);

    UserResponse enableUser(
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);

    UserResponse deleteUser(
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);

    UserResponse restoreUser(
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);

    int cleanSoftDeletedUsers();
}
