package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.oauth2.GitHubLoginRequest;
import com.vaultix.authorization.dto.oauth2.SocialAccountResponse;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@Validated
public interface GitHubAuthService {

    AuthResponse loginWithGitHub(
            @NotNull(message = "GitHub login request cannot be null")
            @Valid GitHubLoginRequest request,
            ClientContext clientContext);

    SocialAccountResponse linkGitHub(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "GitHub login request cannot be null")
            @Valid GitHubLoginRequest request);

    String verifyGitHubCode(
            @NotNull(message = "GitHub login request cannot be null")
            @Valid GitHubLoginRequest request);
}
