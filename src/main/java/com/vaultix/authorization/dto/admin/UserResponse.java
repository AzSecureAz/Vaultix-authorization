package com.vaultix.authorization.dto.admin;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonInclude;
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
        String fullName,
        String phoneNumber,
        UserStatus status,
        boolean emailVerified,
        boolean phoneNumberVerified,
        boolean mfaEnabled,
        boolean passkeyEnabled,
        boolean hasSocialAccounts,
        int failedLoginAttempts,
        Instant lockedUntil,
        Instant lastLoginAt,
        Set<String> roles,
        Instant createdAt,
        UUID createdBy,
        Instant updatedAt,
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
                .phoneNumberVerified(user.isPhoneNumberVerified())
                .mfaEnabled(user.isMfaEnabled())
                .passkeyEnabled(user.isPasskeyEnabled())
                .hasSocialAccounts(user.isHasSocialAccounts())
                .failedLoginAttempts(user.getFailedLoginAttempts())
                .lockedUntil(user.getLockedUntil())
                .lastLoginAt(user.getLastLoginAt())
                .roles(roleNames)
                .createdAt(user.getCreatedAt())
                .createdBy(user.getCreatedBy())
                .updatedAt(user.getUpdatedAt())
                .updatedBy(user.getUpdatedBy())
                .build();
    }
}
