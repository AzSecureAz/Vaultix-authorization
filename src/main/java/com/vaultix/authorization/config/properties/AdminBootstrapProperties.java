package com.vaultix.authorization.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.validation.StrongPassword;
import com.vaultix.authorization.validation.ValidFullName;
import com.vaultix.authorization.validation.ValidUsername;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Validated
@ConfigurationProperties(prefix = "vaultix.admin")
public record AdminBootstrapProperties(
        @DefaultValue("true")
        boolean enabled,
        @NotBlank(message = "Admin username must not be blank")
        @ValidUsername
        @DefaultValue("admin")
        String username,
        @NotBlank(message = "Admin email must not be blank")
        @Email(message = "Admin email must be a valid email address")
        @Size(max = 256, message = "Admin email cannot exceed 256 characters")
        @DefaultValue("admin@vaultix.com")
        String email,
        @NotBlank(message = "Admin password must not be blank")
        @StrongPassword
        @DefaultValue("Admin@Vaultix2026!")
        String password,
        @NotBlank(message = "Admin full name must not be blank")
        @ValidFullName
        @DefaultValue("Vaultix Administrator")
        String fullName) {

}
