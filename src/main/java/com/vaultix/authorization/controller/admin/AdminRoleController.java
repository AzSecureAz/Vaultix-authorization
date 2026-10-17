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

import com.vaultix.authorization.dto.admin.RoleResponse;
import com.vaultix.authorization.security.AuthSecurityExpressions;
import com.vaultix.authorization.service.RoleService;
import com.vaultix.common.dto.ApiResponse;

import jakarta.validation.constraints.NotBlank;
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

        log.info("Admin request to retrieve role with identifier: {}", identifier);
        RoleResponse role = roleService.getRoleByIdentifier(identifier);
        return ResponseEntity.ok(ApiResponse.success("Role retrieved successfully", role));
    }
}
