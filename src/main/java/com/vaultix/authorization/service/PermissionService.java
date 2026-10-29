package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.admin.PermissionResponse;
import com.vaultix.authorization.specification.request.PermissionSearchRequest;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Validated
public interface PermissionService {

    Page<PermissionResponse> getAllPermissions(Pageable pageable);

    Page<PermissionResponse> searchPermissions(@Valid PermissionSearchRequest request, Pageable pageable);

    PermissionResponse getPermissionByIdentifier(
            @NotBlank(message = "Permission identifier is required")
            @Size(max = 128, message = "Permission identifier cannot exceed 128 characters") String identifier);

    PermissionResponse disablePermission(
            @NotBlank(message = "Permission identifier is required")
            @Size(max = 128, message = "Permission identifier cannot exceed 128 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);

    PermissionResponse enablePermission(
            @NotBlank(message = "Permission identifier is required")
            @Size(max = 128, message = "Permission identifier cannot exceed 128 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);
}
