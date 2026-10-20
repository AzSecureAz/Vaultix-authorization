package com.vaultix.authorization.dto.admin;

import java.time.Instant;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.vaultix.authorization.entity.SigningKey;
import com.vaultix.authorization.entity.enums.KeyStatus;

import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SigningKeyResponse(
        UUID id,
        String kid,
        String algorithm,
        String keyUse,
        String publicKeyPem,
        KeyStatus status,
        Instant createdAt,
        UUID createdBy,
        Instant updatedAt,
        UUID updatedBy) {

    public static SigningKeyResponse fromEntity(SigningKey entity) {
        if (entity == null) {
            return null;
        }
        return SigningKeyResponse.builder()
                .id(entity.getId())
                .kid(entity.getKid())
                .algorithm(entity.getAlgorithm())
                .keyUse(entity.getKeyUse())
                .publicKeyPem(entity.getPublicKeyPem())
                .status(entity.getStatus())
                .createdAt(entity.getCreatedAt())
                .createdBy(entity.getCreatedBy())
                .updatedAt(entity.getUpdatedAt())
                .updatedBy(entity.getUpdatedBy())
                .build();
    }
}
