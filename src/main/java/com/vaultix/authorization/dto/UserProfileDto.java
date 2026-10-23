package com.vaultix.authorization.dto;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonInclude;
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
        String fullName,
        String phoneNumber,
        UserStatus status,
        boolean emailVerified,
        boolean phoneNumberVerified,
        boolean mfaEnabled,
        boolean passkeyEnabled,
        boolean hasSocialAccounts,
        Instant lastLoginAt,
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
                .phoneNumberVerified(user.isPhoneNumberVerified())
                .mfaEnabled(user.isMfaEnabled())
                .passkeyEnabled(user.isPasskeyEnabled())
                .hasSocialAccounts(user.isHasSocialAccounts())
                .lastLoginAt(user.getLastLoginAt())
                .createdAt(user.getCreatedAt())
                .roles(roleNames)
                .permissions(permissionNames)
                .build();
    }
}
