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
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.admin.CreateRoleRequest;
import com.vaultix.authorization.dto.admin.RoleResponse;
import com.vaultix.authorization.dto.admin.UpdateRoleRequest;
import com.vaultix.authorization.security.AuthSecurityExpressions;
import com.vaultix.authorization.service.RoleService;
import com.vaultix.authorization.specification.request.RoleSearchRequest;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.security.RequireSudo;
import com.vaultix.common.security.SecurityUtil;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping("/admin/roles")
@RequiredArgsConstructor
public class AdminRoleController {

    private final RoleService roleService;

    @RequireSudo
    @PostMapping
    @PreAuthorize(AuthSecurityExpressions.CAN_CREATE_ROLES)
    public ResponseEntity<ApiResponse<RoleResponse>> createRole(
            @Valid @RequestBody CreateRoleRequest request,
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

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

    @PostMapping("/search")
    @PreAuthorize(AuthSecurityExpressions.CAN_READ_ROLES)
    public ResponseEntity<ApiResponse<Page<RoleResponse>>> searchRoles(
            @Valid @RequestBody(required = false) RoleSearchRequest request,
            @PageableDefault(sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("Admin request to search roles with request: {}, pageable: {}", request, pageable);
        Page<RoleResponse> roles = roleService.searchRoles(request, pageable);
        return ResponseEntity.ok(ApiResponse.success("Roles retrieved successfully", roles));
    }

    @GetMapping("/assignable")
    @PreAuthorize(AuthSecurityExpressions.CAN_CREATE_USERS + " or " + AuthSecurityExpressions.CAN_UPDATE_USERS)
    public ResponseEntity<ApiResponse<Page<RoleResponse>>> getAssignableRoles(
            @RequestParam(value = "search", required = false) String search,
            @PageableDefault(sort = "level", direction = Sort.Direction.ASC) Pageable pageable) {

        log.info("Admin request to retrieve assignable roles for user management with search: '{}', pageable: {}", search, pageable);
        Page<RoleResponse> roles = roleService.getAssignableRoles(search, pageable);
        return ResponseEntity.ok(ApiResponse.success("Assignable roles retrieved successfully", roles));
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

    @RequireSudo
    @RequestMapping(value = "/{identifier}", method = {RequestMethod.PUT, RequestMethod.PATCH})
    @PreAuthorize(AuthSecurityExpressions.CAN_UPDATE_ROLES)
    public ResponseEntity<ApiResponse<RoleResponse>> updateRole(
            @PathVariable("identifier")
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @Valid @RequestBody UpdateRoleRequest request,
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        String cleanIdentifier = identifier.strip();
        UUID actorId = SecurityUtil.extractActorId(jwt);
        log.info("Admin request to update role with identifier: {} by user ID: {}", cleanIdentifier, actorId);
        RoleResponse updatedRole = roleService.updateRole(cleanIdentifier, request, actorId);
        return ResponseEntity.ok(ApiResponse.success("Role updated successfully", updatedRole));
    }

    @RequireSudo
    @PostMapping("/{identifier}/disable")
    @PreAuthorize(AuthSecurityExpressions.CAN_UPDATE_ROLES)
    public ResponseEntity<ApiResponse<RoleResponse>> disableRole(
            @PathVariable("identifier")
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        String cleanIdentifier = identifier.strip();
        UUID actorId = SecurityUtil.extractActorId(jwt);
        log.info("Admin request to disable role with identifier: {} by user ID: {}", cleanIdentifier, actorId);
        RoleResponse disabledRole = roleService.disableRole(cleanIdentifier, actorId);
        return ResponseEntity.ok(ApiResponse.success("Role disabled successfully", disabledRole));
    }

    @RequireSudo
    @PostMapping("/{identifier}/enable")
    @PreAuthorize(AuthSecurityExpressions.CAN_UPDATE_ROLES)
    public ResponseEntity<ApiResponse<RoleResponse>> enableRole(
            @PathVariable("identifier")
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        String cleanIdentifier = identifier.strip();
        UUID actorId = SecurityUtil.extractActorId(jwt);
        log.info("Admin request to enable role with identifier: {} by user ID: {}", cleanIdentifier, actorId);
        RoleResponse enabledRole = roleService.enableRole(cleanIdentifier, actorId);
        return ResponseEntity.ok(ApiResponse.success("Role enabled successfully", enabledRole));
    }

    @RequireSudo
    @DeleteMapping("/{identifier}")
    @PreAuthorize(AuthSecurityExpressions.CAN_DELETE_ROLES)
    public ResponseEntity<ApiResponse<RoleResponse>> deleteRole(
            @PathVariable("identifier")
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        String cleanIdentifier = identifier.strip();
        UUID actorId = SecurityUtil.extractActorId(jwt);
        log.info("Admin request to delete role with identifier: {} by user ID: {}", cleanIdentifier, actorId);
        RoleResponse deletedRole = roleService.deleteRole(cleanIdentifier, actorId);
        return ResponseEntity.ok(ApiResponse.success("Role deleted successfully", deletedRole));
    }

    @RequireSudo
    @PostMapping("/{identifier}/restore")
    @PreAuthorize(AuthSecurityExpressions.CAN_RESTORE_ROLES)
    public ResponseEntity<ApiResponse<RoleResponse>> restoreRole(
            @PathVariable("identifier")
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        String cleanIdentifier = identifier.strip();
        UUID actorId = SecurityUtil.extractActorId(jwt);
        log.info("Admin request to restore role with identifier: {} by user ID: {}", cleanIdentifier, actorId);
        RoleResponse restoredRole = roleService.restoreRole(cleanIdentifier, actorId);
        return ResponseEntity.ok(ApiResponse.success("Role restored successfully", restoredRole));
    }
}
