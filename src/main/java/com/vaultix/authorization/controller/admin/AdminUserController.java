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
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.admin.CreateUserRequest;
import com.vaultix.authorization.dto.admin.UpdateUserRequest;
import com.vaultix.authorization.dto.admin.UserResponse;
import com.vaultix.authorization.security.AuthSecurityExpressions;
import com.vaultix.authorization.service.UserService;
import com.vaultix.authorization.specification.request.UserSearchRequest;
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
@RequestMapping("/admin/users")
@RequiredArgsConstructor
public class AdminUserController {

    private final UserService userService;

    @RequireSudo
    @PostMapping
    @PreAuthorize(AuthSecurityExpressions.CAN_CREATE_USERS)
    public ResponseEntity<ApiResponse<UserResponse>> createUser(
            @Valid @RequestBody CreateUserRequest request,
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID actorId = SecurityUtil.extractActorId(jwt);
        log.info("Admin request to create user with username: '{}' by user ID: {}", request.username(), actorId);
        UserResponse createdUser = userService.createUser(request, actorId);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("User created successfully", createdUser));
    }

    @GetMapping
    @PreAuthorize(AuthSecurityExpressions.CAN_READ_USERS)
    public ResponseEntity<ApiResponse<Page<UserResponse>>> getAllUsers(
            @PageableDefault(sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("Admin request to retrieve users with pageable: {}", pageable);
        Page<UserResponse> users = userService.getAllUsers(pageable);
        return ResponseEntity.ok(ApiResponse.success("Users retrieved successfully", users));
    }

    @PostMapping("/search")
    @PreAuthorize(AuthSecurityExpressions.CAN_READ_USERS)
    public ResponseEntity<ApiResponse<Page<UserResponse>>> searchUsers(
            @Valid @RequestBody(required = false) UserSearchRequest request,
            @PageableDefault(sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("Admin request to search users with request: {}, pageable: {}", request, pageable);
        Page<UserResponse> users = userService.searchUsers(request, pageable);
        return ResponseEntity.ok(ApiResponse.success("Users retrieved successfully", users));
    }

    @GetMapping("/{identifier}")
    @PreAuthorize(AuthSecurityExpressions.CAN_READ_USERS)
    public ResponseEntity<ApiResponse<UserResponse>> getUserByIdentifier(
            @PathVariable("identifier")
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier) {

        String cleanIdentifier = identifier.strip();
        log.info("Admin request to retrieve user with identifier: {}", cleanIdentifier);
        UserResponse user = userService.getUserByIdentifier(cleanIdentifier);
        return ResponseEntity.ok(ApiResponse.success("User retrieved successfully", user));
    }

    @RequireSudo
    @RequestMapping(value = "/{identifier}", method = {RequestMethod.PUT, RequestMethod.PATCH})
    @PreAuthorize(AuthSecurityExpressions.CAN_UPDATE_USERS)
    public ResponseEntity<ApiResponse<UserResponse>> updateUser(
            @PathVariable("identifier")
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @Valid @RequestBody UpdateUserRequest request,
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID actorId = SecurityUtil.extractActorId(jwt);
        String cleanIdentifier = identifier.strip();
        log.info("Admin request to update user '{}' by actor ID: {}", cleanIdentifier, actorId);
        UserResponse updatedUser = userService.updateUser(cleanIdentifier, request, actorId);
        return ResponseEntity.ok(ApiResponse.success("User updated successfully", updatedUser));
    }

    @RequireSudo
    @PostMapping("/{identifier}/disable")
    @PreAuthorize(AuthSecurityExpressions.CAN_UPDATE_USERS)
    public ResponseEntity<ApiResponse<UserResponse>> disableUser(
            @PathVariable("identifier")
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID actorId = SecurityUtil.extractActorId(jwt);
        String cleanIdentifier = identifier.strip();
        log.info("Admin request to disable user '{}' by actor ID: {}", cleanIdentifier, actorId);
        UserResponse disabledUser = userService.disableUser(cleanIdentifier, actorId);
        return ResponseEntity.ok(ApiResponse.success("User disabled successfully", disabledUser));
    }

    @RequireSudo
    @PostMapping("/{identifier}/enable")
    @PreAuthorize(AuthSecurityExpressions.CAN_UPDATE_USERS)
    public ResponseEntity<ApiResponse<UserResponse>> enableUser(
            @PathVariable("identifier")
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID actorId = SecurityUtil.extractActorId(jwt);
        String cleanIdentifier = identifier.strip();
        log.info("Admin request to enable user '{}' by actor ID: {}", cleanIdentifier, actorId);
        UserResponse enabledUser = userService.enableUser(cleanIdentifier, actorId);
        return ResponseEntity.ok(ApiResponse.success("User enabled successfully", enabledUser));
    }

    @RequireSudo
    @DeleteMapping("/{identifier}")
    @PreAuthorize(AuthSecurityExpressions.CAN_DELETE_USERS)
    public ResponseEntity<ApiResponse<UserResponse>> deleteUser(
            @PathVariable("identifier")
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID actorId = SecurityUtil.extractActorId(jwt);
        String cleanIdentifier = identifier.strip();
        log.info("Admin request to delete user '{}' by actor ID: {}", cleanIdentifier, actorId);
        UserResponse deletedUser = userService.deleteUser(cleanIdentifier, actorId);
        return ResponseEntity.ok(ApiResponse.success("User deleted successfully", deletedUser));
    }

    @RequireSudo
    @PostMapping("/{identifier}/restore")
    @PreAuthorize(AuthSecurityExpressions.CAN_RESTORE_USERS)
    public ResponseEntity<ApiResponse<UserResponse>> restoreUser(
            @PathVariable("identifier")
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID actorId = SecurityUtil.extractActorId(jwt);
        String cleanIdentifier = identifier.strip();
        log.info("Admin request to restore user '{}' by actor ID: {}", cleanIdentifier, actorId);
        UserResponse restoredUser = userService.restoreUser(cleanIdentifier, actorId);
        return ResponseEntity.ok(ApiResponse.success("User restored successfully", restoredUser));
    }

    @RequireSudo
    @PostMapping("/{identifier}/reset-mfa")
    @PreAuthorize(AuthSecurityExpressions.CAN_UPDATE_USERS)
    public ResponseEntity<ApiResponse<UserResponse>> resetMfa(
            @PathVariable("identifier")
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID actorId = SecurityUtil.extractActorId(jwt);
        String cleanIdentifier = identifier.strip();
        log.info("Admin request to reset MFA for user '{}' by actor ID: {}", cleanIdentifier, actorId);
        UserResponse updatedUser = userService.resetMfa(cleanIdentifier, actorId);
        return ResponseEntity.ok(ApiResponse.success("Two-factor authentication reset successfully for user", updatedUser));
    }
}
