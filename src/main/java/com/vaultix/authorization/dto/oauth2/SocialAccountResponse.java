package com.vaultix.authorization.dto.oauth2;

import java.time.Instant;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.vaultix.authorization.entity.UserSocialAccount;
import com.vaultix.authorization.entity.enums.SocialProvider;

import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SocialAccountResponse(
        UUID id,
        SocialProvider provider,
        String providerUserId,
        String email,
        String displayName,
        String avatarUrl,
        Instant createdAt) {

    public static SocialAccountResponse fromEntity(UserSocialAccount entity) {
        if (entity == null) {
            return null;
        }
        return SocialAccountResponse.builder()
                .id(entity.getId())
                .provider(entity.getProvider())
                .providerUserId(entity.getProviderUserId())
                .email(entity.getEmail())
                .displayName(entity.getDisplayName())
                .avatarUrl(entity.getAvatarUrl())
                .createdAt(entity.getCreatedAt())
                .build();
    }
}
