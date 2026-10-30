package com.vaultix.authorization.dto;

import java.time.Instant;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.vaultix.authorization.entity.RefreshToken;

import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SessionResponse(
        UUID id,
        String deviceInfo,
        String ipAddress,
        String locationInfo,
        boolean current,
        Instant createdAt,
        Instant lastActiveAt,
        Instant expiresAt) {

    public static SessionResponse fromEntity(RefreshToken entity, UUID currentSessionIdentifier) {
        if (entity == null) {
            return null;
        }

        boolean isCurrent = currentSessionIdentifier != null && (currentSessionIdentifier.equals(entity.getAccessTokenJti())
                || currentSessionIdentifier.equals(entity.getRefreshTokenJti())
                || currentSessionIdentifier.equals(entity.getId()));

        Instant lastActive = entity.getUpdatedAt() != null ? entity.getUpdatedAt() : entity.getCreatedAt();

        return SessionResponse.builder()
                .id(entity.getId())
                .deviceInfo(entity.getDeviceInfo())
                .ipAddress(entity.getIpAddress())
                .locationInfo(entity.getLocationInfo())
                .current(isCurrent)
                .createdAt(entity.getCreatedAt())
                .lastActiveAt(lastActive)
                .expiresAt(entity.getExpiresAt())
                .build();
    }

    public static SessionResponse fromEntity(RefreshToken entity) {
        return fromEntity(entity, null);
    }
}
