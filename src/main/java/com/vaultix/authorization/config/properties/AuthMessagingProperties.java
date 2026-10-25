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
        @NotBlank(message = "Phone verification routing key is required")
        @Size(max = 256, message = "Phone verification routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.phone-verification")
        String phoneVerificationRoutingKey,
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
        @NotBlank(message = "Phone changed routing key is required")
        @Size(max = 256, message = "Phone changed routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.phone-changed")
        String phoneChangedRoutingKey,
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
        @NotBlank(message = "Recovery code used routing key is required")
        @Size(max = 256, message = "Recovery code used routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.recovery-code-used")
        String recoveryCodeUsedRoutingKey,
        @NotBlank(message = "Recovery codes regenerated routing key is required")
        @Size(max = 256, message = "Recovery codes regenerated routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.recovery-codes-regenerated")
        String recoveryCodesRegeneratedRoutingKey,
        @NotBlank(message = "Passkey added routing key is required")
        @Size(max = 256, message = "Passkey added routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.passkey-added")
        String passkeyAddedRoutingKey,
        @NotBlank(message = "Passkey removed routing key is required")
        @Size(max = 256, message = "Passkey removed routing key cannot exceed 256 characters")
        @DefaultValue("auth.notification.passkey-removed")
        String passkeyRemovedRoutingKey) {

}
