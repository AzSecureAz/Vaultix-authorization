package com.vaultix.authorization.dto.admin;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.vaultix.authorization.entity.Role;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.UserStatus;

import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record UserResponse(
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
        @JsonProperty("failed_login_attempts")
        int failedLoginAttempts,
        @JsonProperty("locked_until")
        Instant lockedUntil,
        @JsonProperty("last_login_at")
        Instant lastLoginAt,
        Set<String> roles,
        @JsonProperty("created_at")
        Instant createdAt,
        @JsonProperty("created_by")
        UUID createdBy,
        @JsonProperty("updated_at")
        Instant updatedAt,
        @JsonProperty("updated_by")
        UUID updatedBy) {

    public static UserResponse fromEntity(User user) {
        if (user == null) {
            return null;
        }

        Set<String> roleNames = new HashSet<>();
        if (user.getRoles() != null) {
            for (Role role : user.getRoles()) {
                roleNames.add(role.getName());
            }
        }

        return UserResponse.builder()
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
                .failedLoginAttempts(user.getFailedLoginAttempts())
                .lockedUntil(user.getLockedUntil())
                .lastLoginAt(user.getLastLoginAt())
                .roles(Collections.unmodifiableSet(roleNames))
                .createdAt(user.getCreatedAt())
                .createdBy(user.getCreatedBy())
                .updatedAt(user.getUpdatedAt())
                .updatedBy(user.getUpdatedBy())
                .build();
    }
}
