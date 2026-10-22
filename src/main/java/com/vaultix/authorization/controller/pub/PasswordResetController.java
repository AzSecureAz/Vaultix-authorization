package com.vaultix.authorization.controller.pub;

import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.PasswordResetConfirmRequest;
import com.vaultix.authorization.dto.PasswordResetRequest;
import com.vaultix.authorization.service.PasswordResetService;
import com.vaultix.common.dto.ApiResponse;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping({"/public/password-reset", "/public/password/reset"})
@RequiredArgsConstructor
public class PasswordResetController {

    private final PasswordResetService passwordResetService;

    @PostMapping({"/request", ""})
    public ResponseEntity<ApiResponse<Void>> requestPasswordReset(
            @Valid @RequestBody PasswordResetRequest request) {

        log.info("Public password reset request received");
        passwordResetService.requestPasswordReset(request);
        return ResponseEntity.ok(ApiResponse.success(
                "If an account exists with the provided identifier, a password reset code has been sent."));
    }

    @PostMapping("/confirm")
    public ResponseEntity<ApiResponse<Void>> confirmPasswordReset(
            @Valid @RequestBody PasswordResetConfirmRequest request) {

        log.info("Public password reset confirmation received");
        passwordResetService.confirmPasswordReset(request);
        return ResponseEntity.ok(ApiResponse.success(
                "Password reset successfully. You can now log in with your new password."));
    }
}
