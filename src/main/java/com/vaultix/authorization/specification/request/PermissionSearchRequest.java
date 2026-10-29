package com.vaultix.authorization.specification.request;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import com.vaultix.authorization.entity.enums.PermissionStatus;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record PermissionSearchRequest(
        @Size(max = 128, message = "Search query cannot exceed 128 characters")
        String search,
        @Size(max = 100, message = "Cannot filter by more than 100 IDs at a time")
        Set<@NotNull(message = "Permission ID cannot be null") UUID> ids,
        @Size(max = 100, message = "Cannot filter by more than 100 names at a time")
        Set<@NotBlank(message = "Permission name cannot be blank")
        @Size(max = 128, message = "Permission name cannot exceed 128 characters") String> names,
        Set<@NotNull(message = "Status cannot be null") PermissionStatus> statuses,
        Instant updatedAfter,
        Instant updatedBefore,
        @Size(max = 100, message = "Cannot filter by more than 100 updater IDs at a time")
        Set<@NotNull(message = "Updated by ID cannot be null") UUID> updatedBy) {

}
