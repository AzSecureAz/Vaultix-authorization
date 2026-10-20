package com.vaultix.authorization.dto.admin;

import java.time.Instant;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.vaultix.authorization.entity.Permission;
import com.vaultix.authorization.entity.enums.PermissionStatus;

import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PermissionResponse(
        UUID id,
        String name,
        String description,
        PermissionStatus status,
        Instant createdAt,
        UUID createdBy,
        Instant updatedAt,
        UUID updatedBy) {

    public static PermissionResponse fromEntity(Permission entity) {
        if (entity == null) {
            return null;
        }
        return PermissionResponse.builder()
                .id(entity.getId())
                .name(entity.getName())
                .description(entity.getDescription())
                .status(entity.getStatus())
                .createdAt(entity.getCreatedAt())
                .createdBy(entity.getCreatedBy())
                .updatedAt(entity.getUpdatedAt())
                .updatedBy(entity.getUpdatedBy())
                .build();
    }
}
