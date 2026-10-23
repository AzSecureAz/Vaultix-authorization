package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.ChangePasswordRequest;
import com.vaultix.authorization.dto.ChangeUsernameRequest;
import com.vaultix.authorization.dto.ConfirmEmailChangeRequest;
import com.vaultix.authorization.dto.ConfirmPhoneNumberChangeRequest;
import com.vaultix.authorization.dto.RequestEmailChangeRequest;
import com.vaultix.authorization.dto.RequestPhoneNumberChangeRequest;
import com.vaultix.authorization.dto.RevertEmailRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.dto.VerifyEmailRequest;
import com.vaultix.authorization.dto.VerifyPhoneNumberRequest;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@Validated
public interface AccountService {

    UserProfileDto getProfile(@NotNull(message = "User ID cannot be null") UUID userId);

    void changeUsername(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Change username request cannot be null")
            @Valid ChangeUsernameRequest request);

    void changePassword(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Change password request cannot be null")
            @Valid ChangePasswordRequest request);

    void sendEmailVerification(@NotNull(message = "User ID cannot be null") UUID userId);

    void verifyEmail(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Verification request cannot be null")
            @Valid VerifyEmailRequest request);

    void sendPhoneNumberVerification(@NotNull(message = "User ID cannot be null") UUID userId);

    void verifyPhoneNumber(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Verification request cannot be null")
            @Valid VerifyPhoneNumberRequest request);

    void requestEmailChange(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Request email change request cannot be null")
            @Valid RequestEmailChangeRequest request);

    void confirmEmailChange(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Confirm email change request cannot be null")
            @Valid ConfirmEmailChangeRequest request);

    void requestPhoneNumberChange(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Request phone number change request cannot be null")
            @Valid RequestPhoneNumberChangeRequest request);

    void confirmPhoneNumberChange(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Confirm phone number change request cannot be null")
            @Valid ConfirmPhoneNumberChangeRequest request);

    void revertEmail(
            @NotNull(message = "Revert email request cannot be null")
            @Valid RevertEmailRequest request);
}
