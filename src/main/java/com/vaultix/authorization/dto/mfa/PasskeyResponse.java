package com.vaultix.authorization.dto.mfa;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.vaultix.authorization.entity.UserPasskeyCredential;

import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PasskeyResponse(
        UUID id,
        String credentialId,
        String label,
        String publicKeyCredentialType,
        List<String> transports,
        boolean backupEligible,
        boolean backupState,
        Instant createdAt,
        Instant lastUsedAt) {

    public static PasskeyResponse fromEntity(UserPasskeyCredential credential) {
        if (credential == null) {
            return null;
        }

        List<String> transports = parseTransports(credential.getAuthenticatorTransports());
        return PasskeyResponse.builder()
                .id(credential.getId())
                .credentialId(credential.getCredentialId())
                .label(credential.getLabel())
                .publicKeyCredentialType(credential.getPublicKeyCredentialType())
                .transports(transports)
                .backupEligible(credential.isBackupEligible())
                .backupState(credential.isBackupState())
                .createdAt(credential.getCreatedAt())
                .lastUsedAt(credential.getLastUsedAt())
                .build();
    }

    private static List<String> parseTransports(String rawTransports) {
        if (rawTransports == null || rawTransports.isBlank()) {
            return List.of();
        }
        return Arrays.stream(rawTransports.split(","))
                .map(String::strip)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}
