package com.vaultix.authorization.dto;

import com.vaultix.authorization.dto.oauth2.GitHubLoginRequest;
import com.vaultix.authorization.dto.oauth2.GoogleLoginRequest;
import com.vaultix.authorization.validation.StrongPassword;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;

public record SudoVerifyRequest(
        @Size(max = StrongPassword.MAX_LENGTH, message = "Password cannot exceed " + StrongPassword.MAX_LENGTH + " characters")
        String password,
        @Valid
        GoogleLoginRequest google,
        @Valid
        GitHubLoginRequest github,
        @Size(max = 8192, message = "Google ID token cannot exceed 8192 characters")
        String googleIdToken,
        @Size(max = 256, message = "GitHub authorization code cannot exceed 256 characters")
        String githubCode,
        @Size(max = 1024, message = "GitHub redirect URI cannot exceed 1024 characters")
        String githubRedirectUri,
        @Size(max = 16, message = "TOTP code cannot exceed 16 characters")
        String totpCode,
        @Size(max = 16, message = "SMS OTP cannot exceed 16 characters")
        String smsCode,
        @Size(max = 64, message = "Recovery code cannot exceed 64 characters")
        String recoveryCode) {

    public String resolvedGoogleIdToken() {
        if (google != null && google.idToken() != null && !google.idToken().isBlank()) {
            return google.idToken().strip();
        }
        if (googleIdToken != null && !googleIdToken.isBlank()) {
            return googleIdToken.strip();
        }
        return null;
    }

    public String resolvedGithubCode() {
        if (github != null && github.code() != null && !github.code().isBlank()) {
            return github.code().strip();
        }
        if (githubCode != null && !githubCode.isBlank()) {
            return githubCode.strip();
        }
        return null;
    }

    public String resolvedGithubRedirectUri() {
        if (github != null && github.redirectUri() != null && !github.redirectUri().isBlank()) {
            return github.redirectUri().strip();
        }
        if (githubRedirectUri != null && !githubRedirectUri.isBlank()) {
            return githubRedirectUri.strip();
        }
        return null;
    }
}
