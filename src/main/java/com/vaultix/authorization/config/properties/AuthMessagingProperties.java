package com.vaultix.authorization.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Validated
@ConfigurationProperties(prefix = "vaultix.rabbitmq")
public record AuthMessagingProperties(
        @NotBlank(message = "RabbitMQ exchange name is required")
        @Size(max = 256, message = "RabbitMQ exchange name cannot exceed 256 characters")
        @DefaultValue("auth.exchange")
        String exchange,
        @NotBlank(message = "Password reset routing key is required")
        @Size(max = 256, message = "Password reset routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.password-reset")
        String passwordResetRoutingKey,
        @NotBlank(message = "Email verification routing key is required")
        @Size(max = 256, message = "Email verification routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.email-verification")
        String emailVerificationRoutingKey,
        @NotBlank(message = "Welcome routing key is required")
        @Size(max = 256, message = "Welcome routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.welcome")
        String welcomeRoutingKey,
        @NotBlank(message = "Password changed routing key is required")
        @Size(max = 256, message = "Password changed routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.password-changed")
        String passwordChangedRoutingKey,
        @NotBlank(message = "Email changed routing key is required")
        @Size(max = 256, message = "Email changed routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.email-changed")
        String emailChangedRoutingKey,
        @NotBlank(message = "Email reverted routing key is required")
        @Size(max = 256, message = "Email reverted routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.email-reverted")
        String emailRevertedRoutingKey,
        @NotBlank(message = "MFA enabled routing key is required")
        @Size(max = 256, message = "MFA enabled routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.mfa-enabled")
        String mfaEnabledRoutingKey,
        @NotBlank(message = "MFA disabled routing key is required")
        @Size(max = 256, message = "MFA disabled routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.mfa-disabled")
        String mfaDisabledRoutingKey,
        @NotBlank(message = "MFA login OTP routing key is required")
        @Size(max = 256, message = "MFA login OTP routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.mfa-login-otp")
        String mfaLoginOtpRoutingKey) {

}
