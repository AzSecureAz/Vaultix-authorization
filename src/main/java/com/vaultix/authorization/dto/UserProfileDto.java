package com.vaultix.authorization.dto;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
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
        Set<String> roles,
        Set<String> permissions) {

    public static UserProfileDto fromEntity(User user) {
        if (user == null) {
            return null;
        }

        Set<String> roleNames = new HashSet<>();
        Set<String> permissionNames = new HashSet<>();

        if (user.getRoles() != null) {
            for (Role role : user.getRoles()) {
                if (role.getStatus() == RoleStatus.ENABLED) {
                    roleNames.add(role.getName());
                    if (role.getPermissions() != null) {
                        for (Permission perm : role.getPermissions()) {
                            if (perm.getStatus() == PermissionStatus.ENABLED) {
                                permissionNames.add(perm.getName());
                            }
                        }
                    }
                }
            }
        }

        return UserProfileDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .phoneNumber(user.getPhoneNumber())
                .status(user.getStatus())
                .emailVerified(user.isEmailVerified())
                .mfaEnabled(user.isMfaEnabled())
                .passkeyEnabled(user.isPasskeyEnabled())
                .hasSocialAccounts(user.isHasSocialAccounts())
                .lastLoginAt(user.getLastLoginAt())
                .createdAt(user.getCreatedAt())
                .roles(Collections.unmodifiableSet(roleNames))
                .permissions(Collections.unmodifiableSet(permissionNames))
                .build();
    }
}
