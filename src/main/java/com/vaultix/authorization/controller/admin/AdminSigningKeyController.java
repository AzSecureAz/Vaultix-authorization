package com.vaultix.authorization.controller.admin;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.admin.SigningKeyResponse;
import com.vaultix.authorization.security.AuthSecurityExpressions;
import com.vaultix.authorization.service.SigningKeyService;
import com.vaultix.common.dto.ApiResponse;

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
}
