package com.vaultix.authorization.specification.request;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import com.vaultix.authorization.entity.enums.UserStatus;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record UserSearchRequest(
        @Size(max = 256, message = "Search query cannot exceed 256 characters")
        String search,
        @Size(max = 100, message = "Cannot filter by more than 100 IDs at a time")
        Set<@NotNull(message = "User ID cannot be null") UUID> ids,
        @Size(max = 100, message = "Cannot filter by more than 100 usernames at a time")
        Set<@NotBlank(message = "Username cannot be blank")
        @Size(max = 128, message = "Username cannot exceed 128 characters") String> usernames,
        @Size(max = 100, message = "Cannot filter by more than 100 emails at a time")
        Set<@NotBlank(message = "Email cannot be blank")
        @Size(max = 256, message = "Email cannot exceed 256 characters") String> emails,
        @Size(max = 100, message = "Cannot filter by more than 100 phone numbers at a time")
        Set<@NotBlank(message = "Phone number cannot be blank")
        @Size(max = 32, message = "Phone number cannot exceed 32 characters") String> phoneNumbers,
        Set<@NotNull(message = "Status cannot be null") UserStatus> statuses,
        @Size(max = 50, message = "Cannot filter by more than 50 roles at a time")
        Set<@NotBlank(message = "Role name cannot be blank")
        @Size(max = 64, message = "Role name cannot exceed 64 characters") String> roles,
        Boolean emailVerified,
        Boolean phoneNumberVerified,
        Boolean mfaEnabled,
        Boolean passkeyEnabled,
        Boolean smsMfaEnabled,
        Boolean hasSocialAccounts,
        Boolean hasPassword,
        @Min(value = 0, message = "Minimum failed login attempts cannot be negative")
        Integer minFailedLoginAttempts,
        @Min(value = 0, message = "Maximum failed login attempts cannot be negative")
        Integer maxFailedLoginAttempts,
        Instant lockedUntilAfter,
        Instant lockedUntilBefore,
        Instant lastLoginAfter,
        Instant lastLoginBefore,
        Instant createdAfter,
        Instant createdBefore,
        @Size(max = 100, message = "Cannot filter by more than 100 creator IDs at a time")
        Set<@NotNull(message = "Created by ID cannot be null") UUID> createdBy,
        Instant updatedAfter,
        Instant updatedBefore,
        @Size(max = 100, message = "Cannot filter by more than 100 updater IDs at a time")
        Set<@NotNull(message = "Updated by ID cannot be null") UUID> updatedBy) {

}
