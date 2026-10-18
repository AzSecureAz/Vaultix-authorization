package com.vaultix.authorization.controller.admin;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.admin.CreateRoleRequest;
import com.vaultix.authorization.dto.admin.RoleResponse;
import com.vaultix.authorization.dto.admin.UpdateRoleRequest;
import com.vaultix.authorization.security.AuthSecurityExpressions;
import com.vaultix.authorization.service.RoleService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.security.SecurityUtil;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/admin/roles")
@RequiredArgsConstructor
public class AdminRoleController {

    private final RoleService roleService;

    @PostMapping
    @PreAuthorize(AuthSecurityExpressions.CAN_CREATE_ROLES)
    public ResponseEntity<ApiResponse<RoleResponse>> createRole(
            @Valid @RequestBody CreateRoleRequest request,
            @AuthenticationPrincipal Jwt jwt) {

        UUID actorId = SecurityUtil.extractActorId(jwt);
        log.info("Admin request to create role with name: '{}' by user ID: {}", request.name(), actorId);
        RoleResponse createdRole = roleService.createRole(request, actorId);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Role created successfully", createdRole));
    }

    @GetMapping
    @PreAuthorize(AuthSecurityExpressions.CAN_READ_ROLES)
    public ResponseEntity<ApiResponse<Page<RoleResponse>>> getAllRoles(
            @PageableDefault(sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("Admin request to retrieve roles with pageable: {}", pageable);
        Page<RoleResponse> roles = roleService.getAllRoles(pageable);
        return ResponseEntity.ok(ApiResponse.success("Roles retrieved successfully", roles));
    }

    @GetMapping("/{identifier}")
    @PreAuthorize(AuthSecurityExpressions.CAN_READ_ROLES)
    public ResponseEntity<ApiResponse<RoleResponse>> getRoleByIdentifier(
            @PathVariable("identifier")
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier) {

        String cleanIdentifier = identifier.strip();
        log.info("Admin request to retrieve role with identifier: {}", cleanIdentifier);
        RoleResponse role = roleService.getRoleByIdentifier(cleanIdentifier);
        return ResponseEntity.ok(ApiResponse.success("Role retrieved successfully", role));
    }

    @PutMapping("/{identifier}")
    @PreAuthorize(AuthSecurityExpressions.CAN_UPDATE_ROLES)
    public ResponseEntity<ApiResponse<RoleResponse>> updateRole(
            @PathVariable("identifier")
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @Valid @RequestBody UpdateRoleRequest request,
            @AuthenticationPrincipal Jwt jwt) {

        String cleanIdentifier = identifier.strip();
        UUID actorId = SecurityUtil.extractActorId(jwt);
        log.info("Admin request to update role with identifier: {} by user ID: {}", cleanIdentifier, actorId);
        RoleResponse updatedRole = roleService.updateRole(cleanIdentifier, request, actorId);
        return ResponseEntity.ok(ApiResponse.success("Role updated successfully", updatedRole));
    }

    @PostMapping("/{identifier}/disable")
    @PreAuthorize(AuthSecurityExpressions.CAN_UPDATE_ROLES)
    public ResponseEntity<ApiResponse<RoleResponse>> disableRole(
            @PathVariable("identifier")
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @AuthenticationPrincipal Jwt jwt) {

        String cleanIdentifier = identifier.strip();
        UUID actorId = SecurityUtil.extractActorId(jwt);
        log.info("Admin request to disable role with identifier: {} by user ID: {}", cleanIdentifier, actorId);
        RoleResponse disabledRole = roleService.disableRole(cleanIdentifier, actorId);
        return ResponseEntity.ok(ApiResponse.success("Role disabled successfully", disabledRole));
    }

    @PostMapping("/{identifier}/enable")
    @PreAuthorize(AuthSecurityExpressions.CAN_UPDATE_ROLES)
    public ResponseEntity<ApiResponse<RoleResponse>> enableRole(
            @PathVariable("identifier")
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @AuthenticationPrincipal Jwt jwt) {

        String cleanIdentifier = identifier.strip();
        UUID actorId = SecurityUtil.extractActorId(jwt);
        log.info("Admin request to enable role with identifier: {} by user ID: {}", cleanIdentifier, actorId);
        RoleResponse enabledRole = roleService.enableRole(cleanIdentifier, actorId);
        return ResponseEntity.ok(ApiResponse.success("Role enabled successfully", enabledRole));
    }
}
