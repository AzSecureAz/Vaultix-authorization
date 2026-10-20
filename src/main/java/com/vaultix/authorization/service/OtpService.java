package com.vaultix.authorization.service;

import java.time.Duration;

import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Validated
public interface OtpService {

    String generateOtp(
            @NotBlank(message = "Purpose is required")
            @Size(max = 64, message = "Purpose cannot exceed 64 characters") String purpose,
            @NotBlank(message = "Identifier is required")
            @Size(max = 256, message = "Identifier cannot exceed 256 characters") String identifier,
            Duration ttl);

    String generateOtp(
            @NotBlank(message = "Purpose is required")
            @Size(max = 64, message = "Purpose cannot exceed 64 characters") String purpose,
            @NotBlank(message = "Identifier is required")
            @Size(max = 256, message = "Identifier cannot exceed 256 characters") String identifier);

    boolean verifyOtp(
            @NotBlank(message = "Purpose is required")
            @Size(max = 64, message = "Purpose cannot exceed 64 characters") String purpose,
            @NotBlank(message = "Identifier is required")
            @Size(max = 256, message = "Identifier cannot exceed 256 characters") String identifier,
            @NotBlank(message = "Candidate OTP is required")
            @Size(max = 16, message = "Candidate OTP cannot exceed 16 characters") String candidateOtp);

    void clearOtp(
            @NotBlank(message = "Purpose is required")
            @Size(max = 64, message = "Purpose cannot exceed 64 characters") String purpose,
            @NotBlank(message = "Identifier is required")
            @Size(max = 256, message = "Identifier cannot exceed 256 characters") String identifier);
}
