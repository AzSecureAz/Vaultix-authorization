package com.vaultix.authorization.dto.admin;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.vaultix.authorization.entity.Permission;
import com.vaultix.authorization.entity.Role;
import com.vaultix.authorization.entity.enums.RoleStatus;

import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record RoleResponse(
        UUID id,
        String name,
        String description,
        Integer level,
        RoleStatus status,
        Set<String> permissions,
        @JsonProperty("created_at")
        Instant createdAt,
        @JsonProperty("created_by")
        UUID createdBy,
        @JsonProperty("updated_at")
        Instant updatedAt,
        @JsonProperty("updated_by")
        UUID updatedBy) {

    public static RoleResponse fromEntity(Role entity) {
        if (entity == null) {
            return null;
        }

        Set<String> permissionNames = new HashSet<>();
        if (entity.getPermissions() != null) {
            for (Permission perm : entity.getPermissions()) {
                permissionNames.add(perm.getName());
            }
        }

        return RoleResponse.builder()
                .id(entity.getId())
                .name(entity.getName())
                .description(entity.getDescription())
                .level(entity.getLevel())
                .status(entity.getStatus())
                .permissions(permissionNames)
                .createdAt(entity.getCreatedAt())
                .createdBy(entity.getCreatedBy())
                .updatedAt(entity.getUpdatedAt())
                .updatedBy(entity.getUpdatedBy())
                .build();
    }
}
