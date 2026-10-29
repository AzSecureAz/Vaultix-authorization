package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.admin.CreateRoleRequest;
import com.vaultix.authorization.dto.admin.RoleResponse;
import com.vaultix.authorization.dto.admin.UpdateRoleRequest;
import com.vaultix.authorization.specification.request.RoleSearchRequest;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Validated
public interface RoleService {

    Page<RoleResponse> getAllRoles(Pageable pageable);

    Page<RoleResponse> searchRoles(@Valid RoleSearchRequest request, Pageable pageable);

    Page<RoleResponse> getAssignableRoles(String search, Pageable pageable);

    RoleResponse getRoleByIdentifier(
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier);

    RoleResponse createRole(
            @NotNull(message = "Create role request cannot be null")
            @Valid CreateRoleRequest request,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);

    RoleResponse updateRole(
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @NotNull(message = "Update role request cannot be null")
            @Valid UpdateRoleRequest request,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);

    RoleResponse disableRole(
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);

    RoleResponse enableRole(
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);

    RoleResponse deleteRole(
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);

    RoleResponse restoreRole(
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);

    int cleanSoftDeletedRoles();
}
