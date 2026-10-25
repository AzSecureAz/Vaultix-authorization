package com.vaultix.authorization.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class GoogleAuthConfig {

    public static final String GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";

    @Bean(name = "googleIdTokenDecoder")
    @ConditionalOnMissingBean(name = "googleIdTokenDecoder")
    public JwtDecoder googleIdTokenDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(GOOGLE_JWKS_URI).build();
    }
}
