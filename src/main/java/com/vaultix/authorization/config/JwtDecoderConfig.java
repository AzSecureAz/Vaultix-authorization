package com.vaultix.authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.vaultix.authorization.config.properties.JwtProperties;
import com.vaultix.authorization.service.SigningKeyService;
import com.vaultix.common.security.CommonJwtDecoderFactory;
import com.vaultix.common.security.JwtBlacklistValidator;

@Configuration
public class JwtDecoderConfig {

    @Bean
    public JwtDecoder jwtDecoder(
            SigningKeyService signingKeyService,
            JwtBlacklistValidator jwtBlacklistValidator,
            JwtProperties jwtProperties) {

        JWKSource<SecurityContext> jwkSource = (selector, ctx) -> selector.select(signingKeyService.getJwkSet());
        return CommonJwtDecoderFactory.create(jwkSource, jwtProperties.issuer(), jwtBlacklistValidator);
    }
}
