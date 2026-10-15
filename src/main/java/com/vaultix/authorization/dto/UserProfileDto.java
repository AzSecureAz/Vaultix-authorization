package com.vaultix.authorization.dto;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.vaultix.authorization.entity.Permission;
import com.vaultix.authorization.entity.Role;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.PermissionStatus;
import com.vaultix.authorization.entity.enums.RoleStatus;
import com.vaultix.authorization.entity.enums.UserStatus;

import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record UserProfileDto(
        UUID id,
        String username,
        String email,
        @JsonProperty("full_name")
        String fullName,
        @JsonProperty("phone_number")
        String phoneNumber,
        UserStatus status,
        @JsonProperty("email_verified")
        boolean emailVerified,
        @JsonProperty("must_change_password")
        boolean mustChangePassword,
        @JsonProperty("mfa_enabled")
        boolean mfaEnabled,
        @JsonProperty("passkey_enabled")
        boolean passkeyEnabled,
        @JsonProperty("has_social_accounts")
        boolean hasSocialAccounts,
        @JsonProperty("last_login_at")
        Instant lastLoginAt,
        @JsonProperty("created_at")
        Instant createdAt,
        @JsonProperty("created_by")
        UUID createdBy,
        @JsonProperty("updated_at")
        Instant updatedAt,
        @JsonProperty("updated_by")
        UUID updatedBy,
        @JsonProperty("roles_permissions")
        Map<String, Set<String>> rolePermissions) {

    public static UserProfileDto from(User user) {
        if (user == null) {
            return null;
        }

        Map<String, Set<String>> rolePermissions = new HashMap<>();
        if (user.getRoles() != null) {
            for (Role role : user.getRoles()) {
                if (role.getStatus() == RoleStatus.ENABLED) {
                    Set<String> perms = new HashSet<>();
                    if (role.getPermissions() != null) {
                        for (Permission perm : role.getPermissions()) {
                            if (perm.getStatus() == PermissionStatus.ENABLED) {
                                perms.add(perm.getName());
                            }
                        }
                    }
                    rolePermissions.put(role.getName(), perms);
                }
            }
        }

        return from(user, rolePermissions);
    }

    public static UserProfileDto from(User user, Map<String, Set<String>> rolePermissions) {
        if (user == null) {
            return null;
        }

        return UserProfileDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .phoneNumber(user.getPhoneNumber())
                .status(user.getStatus())
                .emailVerified(user.isEmailVerified())
                .mustChangePassword(user.isMustChangePassword())
                .mfaEnabled(user.isMfaEnabled())
                .passkeyEnabled(user.isPasskeyEnabled())
                .hasSocialAccounts(user.isHasSocialAccounts())
                .lastLoginAt(user.getLastLoginAt())
                .createdAt(user.getCreatedAt())
                .createdBy(user.getCreatedBy())
                .updatedAt(user.getUpdatedAt())
                .updatedBy(user.getUpdatedBy())
                .rolePermissions(rolePermissions)
                .build();
    }
}
