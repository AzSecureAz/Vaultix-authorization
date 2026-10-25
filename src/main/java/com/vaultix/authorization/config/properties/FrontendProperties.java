package com.vaultix.authorization.config.properties;

import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Validated
@ConfigurationProperties(prefix = "vaultix.frontend")
public record FrontendProperties(
        @NotBlank(message = "Frontend base URL cannot be blank")
        @URL(message = "Frontend base URL must be a valid URL")
        @Size(max = 1024, message = "Frontend base URL cannot exceed 1024 characters")
        @DefaultValue("https://zj153pc4-3000.inc1.devtunnels.ms")
        String baseUrl) {

}
