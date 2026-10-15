package com.vaultix.authorization.dto;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;

@Builder
public record UserSummaryDto(
        UUID id,
        String username,
        String email,
        @JsonProperty("email_verified")
        boolean emailVerified,
        @JsonProperty("mfa_enabled")
        boolean mfaEnabled,
        @JsonProperty("passkey_enabled")
        boolean passkeyEnabled,
        @JsonProperty("has_social_accounts")
        boolean hasSocialAccounts,
        @JsonProperty("roles_permissions")
        Map<String, Set<String>> rolePermissions) {

}
