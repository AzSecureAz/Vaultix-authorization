package com.vaultix.authorization.controller.admin;

import java.util.Locale;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.admin.PermissionResponse;
import com.vaultix.authorization.security.AuthSecurityExpressions;
import com.vaultix.authorization.service.PermissionService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.security.CommonSecurityExpressions;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping("/admin/permissions")
@RequiredArgsConstructor
public class AdminPermissionController {

    private final PermissionService permissionService;

    @GetMapping
    @PreAuthorize(AuthSecurityExpressions.CAN_READ_PERMISSIONS)
    public ResponseEntity<ApiResponse<Page<PermissionResponse>>> getAllPermissions(
            @PageableDefault(sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("Admin request to retrieve permissions with pageable: {}", pageable);
        Page<PermissionResponse> permissions = permissionService.getAllPermissions(pageable);
        return ResponseEntity.ok(ApiResponse.success("Permissions retrieved successfully", permissions));
    }

    @GetMapping("/{identifier}")
    @PreAuthorize(AuthSecurityExpressions.CAN_READ_PERMISSIONS)
    public ResponseEntity<ApiResponse<PermissionResponse>> getPermissionByIdentifier(
            @PathVariable("identifier")
            @NotBlank(message = "Permission identifier is required")
            @Size(max = 128, message = "Permission identifier cannot exceed 128 characters") String identifier) {

        String cleanIdentifier = identifier.strip().toLowerCase(Locale.ROOT);
        log.info("Admin request to retrieve permission with identifier: {}", cleanIdentifier);
        PermissionResponse permission = permissionService.getPermissionByIdentifier(cleanIdentifier);
        return ResponseEntity.ok(ApiResponse.success("Permission retrieved successfully", permission));
    }

    @PostMapping("/{identifier}/disable")
    @PreAuthorize(CommonSecurityExpressions.IS_ADMIN)
    public ResponseEntity<ApiResponse<PermissionResponse>> disablePermission(
            @PathVariable("identifier")
            @NotBlank(message = "Permission identifier is required")
            @Size(max = 128, message = "Permission identifier cannot exceed 128 characters") String identifier,
            @AuthenticationPrincipal Jwt jwt) {

        String cleanIdentifier = identifier.strip().toLowerCase(Locale.ROOT);
        UUID actorId = extractActorId(jwt);
        log.info("Admin request to disable permission with identifier: {} by user ID: {}", cleanIdentifier, actorId);
        PermissionResponse disabledPermission = permissionService.disablePermission(cleanIdentifier, actorId);
        return ResponseEntity.ok(ApiResponse.success("Permission disabled successfully", disabledPermission));
    }

    @PostMapping("/{identifier}/enable")
    @PreAuthorize(CommonSecurityExpressions.IS_ADMIN)
    public ResponseEntity<ApiResponse<PermissionResponse>> enablePermission(
            @PathVariable("identifier")
            @NotBlank(message = "Permission identifier is required")
            @Size(max = 128, message = "Permission identifier cannot exceed 128 characters") String identifier,
            @AuthenticationPrincipal Jwt jwt) {

        String cleanIdentifier = identifier.strip().toLowerCase(Locale.ROOT);
        UUID actorId = extractActorId(jwt);
        log.info("Admin request to enable permission with identifier: {} by user ID: {}", cleanIdentifier, actorId);
        PermissionResponse enabledPermission = permissionService.enablePermission(cleanIdentifier, actorId);
        return ResponseEntity.ok(ApiResponse.success("Permission enabled successfully", enabledPermission));
    }

    private UUID extractActorId(Jwt jwt) {
        if (jwt == null || jwt.getSubject() == null || jwt.getSubject().isBlank()) {
            throw new BadCredentialsException("Invalid or missing authentication token");
        }
        try {
            return UUID.fromString(jwt.getSubject().strip());
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException("Invalid actor ID in authentication token");
        }
    }
}
