package com.vaultix.authorization.controller.admin;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.admin.PermissionResponse;
import com.vaultix.authorization.security.AuthSecurityExpressions;
import com.vaultix.authorization.service.PermissionService;
import com.vaultix.common.dto.ApiResponse;

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

        log.info("Admin request to retrieve permission with identifier: {}", identifier);
        PermissionResponse permission = permissionService.getPermissionByIdentifier(identifier);
        return ResponseEntity.ok(ApiResponse.success("Permission retrieved successfully", permission));
    }
}
