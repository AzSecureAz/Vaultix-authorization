package com.vaultix.authorization.specification.request;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import com.vaultix.authorization.entity.enums.KeyStatus;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record SigningKeySearchRequest(
        @Size(max = 64, message = "Search query cannot exceed 64 characters")
        String search,
        Set<@NotNull(message = "Status cannot be null") KeyStatus> statuses,
        Instant createdAfter,
        Instant createdBefore,
        @Size(max = 100, message = "Cannot filter by more than 100 creator IDs at a time")
        Set<@NotNull(message = "Created by ID cannot be null") UUID> createdBy,
        Instant updatedAfter,
        Instant updatedBefore,
        @Size(max = 100, message = "Cannot filter by more than 100 updater IDs at a time")
        Set<@NotNull(message = "Updated by ID cannot be null") UUID> updatedBy) {

}
