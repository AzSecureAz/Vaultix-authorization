package com.vaultix.authorization.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Validated
@ConfigurationProperties(prefix = "vaultix.security.kek")
public record KekProperties(
        @NotBlank(message = "Master Key (KEK) must not be blank")
        @Size(min = 44, max = 44, message = "Master Key (KEK) must be a 44-character Base64-encoded 256-bit AES key")
        @DefaultValue("3xhw5B4DZicmirWLS4h3ZkA4pBFZwyKlG6cvEYvdf7I=")
        String masterKey) {

}
