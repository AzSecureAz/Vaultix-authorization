package com.vaultix.authorization.controller.admin;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.admin.SigningKeyResponse;
import com.vaultix.authorization.security.AuthSecurityExpressions;
import com.vaultix.authorization.service.SigningKeyService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.security.CommonSecurityExpressions;
import com.vaultix.common.security.SecurityUtil;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/admin/signing-keys")
@RequiredArgsConstructor
public class AdminSigningKeyController {

    private final SigningKeyService signingKeyService;

    @GetMapping
    @PreAuthorize(AuthSecurityExpressions.CAN_READ_KEYS)
    public ResponseEntity<ApiResponse<Page<SigningKeyResponse>>> getAllSigningKeys(
            @PageableDefault(sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("Admin request to retrieve signing keys with pageable: {}", pageable);
        Page<SigningKeyResponse> keys = signingKeyService.getAllSigningKeys(pageable);
        return ResponseEntity.ok(ApiResponse.success("Cryptographic signing keys retrieved successfully", keys));
    }

    @GetMapping("/{kid}")
    @PreAuthorize(AuthSecurityExpressions.CAN_READ_KEYS)
    public ResponseEntity<ApiResponse<SigningKeyResponse>> getSigningKeyByKid(
            @PathVariable("kid")
            @NotBlank(message = "Key ID is required")
            @Size(max = 64, message = "Key ID cannot exceed 64 characters") String kid) {

        String cleanKid = kid.strip();
        log.info("Admin request to retrieve signing key with kid: {}", cleanKid);
        SigningKeyResponse key = signingKeyService.getKeyByKid(cleanKid);
        return ResponseEntity.ok(ApiResponse.success("Cryptographic signing key retrieved successfully", key));
    }

    @PostMapping("/rotate")
    @PreAuthorize(AuthSecurityExpressions.CAN_ROTATE_KEYS)
    public ResponseEntity<ApiResponse<SigningKeyResponse>> rotateSigningKey(
            @AuthenticationPrincipal Jwt jwt) {

        UUID actorId = SecurityUtil.extractActorId(jwt);
        log.info("Admin request to manually rotate signing key by user ID: {}", actorId);
        SigningKeyResponse rotatedKey = signingKeyService.rotateKey(actorId);
        return ResponseEntity.ok(ApiResponse.success("Cryptographic signing key rotated successfully", rotatedKey));
    }

    @PostMapping("/{kid}/revoke")
    @PreAuthorize(CommonSecurityExpressions.IS_ADMIN)
    public ResponseEntity<ApiResponse<SigningKeyResponse>> revokeSigningKey(
            @PathVariable("kid")
            @NotBlank(message = "Key ID is required")
            @Size(max = 64, message = "Key ID cannot exceed 64 characters") String kid,
            @AuthenticationPrincipal Jwt jwt) {

        String cleanKid = kid.strip();
        UUID actorId = SecurityUtil.extractActorId(jwt);
        log.info("Admin request to revoke signing key with kid: {} by user ID: {}", cleanKid, actorId);
        SigningKeyResponse revokedKey = signingKeyService.revokeKey(cleanKid, actorId);
        return ResponseEntity.ok(ApiResponse.success("Cryptographic signing key revoked successfully", revokedKey));
    }
}
