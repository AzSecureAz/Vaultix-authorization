package com.vaultix.authorization.service;

import java.util.List;
import java.util.UUID;

import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.oauth2.SocialAccountResponse;
import com.vaultix.authorization.entity.enums.SocialProvider;

import jakarta.validation.constraints.NotNull;

@Validated
public interface SocialAccountService {

    List<SocialAccountResponse> getLinkedAccounts(@NotNull(message = "User ID cannot be null") UUID userId);

    void unlinkAccount(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Social provider cannot be null") SocialProvider provider);
}
