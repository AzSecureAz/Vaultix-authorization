package com.vaultix.authorization.controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.service.AuthService;
import com.vaultix.authorization.service.SigningKeyService;
import com.vaultix.common.dto.ApiResponse;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final SigningKeyService signingKeyService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<String>> login(@Valid @RequestBody LoginRequest request) {
        String userDetails = authService.login(request);
        return ResponseEntity.ok(ApiResponse.success("Authentication successful", userDetails));
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> getJwks() {
        return signingKeyService.getJwkSetAsMap();
    }
}
