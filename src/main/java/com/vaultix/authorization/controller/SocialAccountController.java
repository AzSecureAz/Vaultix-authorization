package com.vaultix.authorization.controller;

import java.util.List;
import java.util.Locale;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.oauth2.GitHubLoginRequest;
import com.vaultix.authorization.dto.oauth2.GoogleLoginRequest;
import com.vaultix.authorization.dto.oauth2.SocialAccountResponse;
import com.vaultix.authorization.entity.enums.SocialProvider;
import com.vaultix.authorization.service.GitHubAuthService;
import com.vaultix.authorization.service.GoogleAuthService;
import com.vaultix.authorization.service.SocialAccountService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.exception.BadRequestException;
import com.vaultix.common.security.RequireSudo;
import com.vaultix.common.security.SecurityUtil;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping("/social")
@RequiredArgsConstructor
public class SocialAccountController {

    private final SocialAccountService socialAccountService;
    private final GoogleAuthService googleAuthService;
    private final GitHubAuthService gitHubAuthService;

    @GetMapping
    public ResponseEntity<ApiResponse<List<SocialAccountResponse>>> getLinkedAccounts(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        List<SocialAccountResponse> accounts = socialAccountService.getLinkedAccounts(userId);
        return ResponseEntity.ok(ApiResponse.success("Linked social accounts retrieved successfully", accounts));
    }

    @RequireSudo
    @PostMapping({"/google/link", "/google"})
    public ResponseEntity<ApiResponse<SocialAccountResponse>> linkGoogle(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody GoogleLoginRequest request) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        SocialAccountResponse response = googleAuthService.linkGoogle(userId, request);
        return ResponseEntity.ok(ApiResponse.success("Google account linked successfully", response));
    }

    @RequireSudo
    @PostMapping({"/github/link", "/github"})
    public ResponseEntity<ApiResponse<SocialAccountResponse>> linkGitHub(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody GitHubLoginRequest request) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        SocialAccountResponse response = gitHubAuthService.linkGitHub(userId, request);
        return ResponseEntity.ok(ApiResponse.success("GitHub account linked successfully", response));
    }

    @RequireSudo
    @DeleteMapping({"/{provider}", "/{provider}/unlink"})
    public ResponseEntity<ApiResponse<Void>> unlinkAccount(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @PathVariable("provider") String providerStr) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        SocialProvider provider;
        try {
            provider = SocialProvider.valueOf(providerStr.strip().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new BadRequestException("Unsupported social provider: " + providerStr);
        }

        socialAccountService.unlinkAccount(userId, provider);
        return ResponseEntity.ok(ApiResponse.success(provider.name() + " account unlinked successfully"));
    }
}
