package com.vaultix.authorization.dto.admin;

import java.time.Instant;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.vaultix.authorization.entity.SigningKey;
import com.vaultix.authorization.entity.enums.KeyStatus;

import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SigningKeyResponse(
        UUID id,
        String kid,
        String algorithm,
        @JsonProperty("key_use")
        String keyUse,
        @JsonProperty("public_key_pem")
        String publicKeyPem,
        KeyStatus status,
        @JsonProperty("created_at")
        Instant createdAt,
        @JsonProperty("created_by")
        UUID createdBy,
        @JsonProperty("updated_at")
        Instant updatedAt,
        @JsonProperty("updated_by")
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
