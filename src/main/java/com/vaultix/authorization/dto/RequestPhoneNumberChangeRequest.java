package com.vaultix.authorization.dto;

import com.vaultix.authorization.validation.ValidPhoneNumber;

import jakarta.validation.constraints.NotBlank;

public record RequestPhoneNumberChangeRequest(
        @NotBlank(message = "New phone number is required")
        @ValidPhoneNumber
        String newPhoneNumber) {

}
