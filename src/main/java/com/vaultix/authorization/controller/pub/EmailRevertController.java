package com.vaultix.authorization.controller.pub;

import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.RevertEmailRequest;
import com.vaultix.authorization.service.AccountService;
import com.vaultix.common.dto.ApiResponse;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping({"/public/email/revert", "/public/email-revert"})
@RequiredArgsConstructor
public class EmailRevertController {

    private final AccountService accountService;

    @PostMapping
    public ResponseEntity<ApiResponse<Void>> revertEmailPost(
            @Valid @RequestBody RevertEmailRequest request) {

        log.info("Received public email revert POST request");
        accountService.revertEmail(request);
        return ResponseEntity.ok(ApiResponse.success(
                "Email successfully reverted to your previous address. All active sessions have been terminated and your password has been cleared for security. Please use password reset to set a new password."));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<Void>> revertEmailGet(
            @RequestParam("token")
            @NotBlank(message = "Revert token is required")
            @Size(max = 128, message = "Revert token cannot exceed 128 characters") String token) {

        log.info("Received public email revert GET request via link");
        accountService.revertEmail(new RevertEmailRequest(token.strip()));
        return ResponseEntity.ok(ApiResponse.success(
                "Email successfully reverted to your previous address. All active sessions have been terminated and your password has been cleared for security. Please use password reset to set a new password."));
    }
}
