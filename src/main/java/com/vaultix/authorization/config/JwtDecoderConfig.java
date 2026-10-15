package com.vaultix.authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.vaultix.authorization.config.properties.JwtProperties;
import com.vaultix.authorization.service.SigningKeyService;
import com.vaultix.common.security.JwtBlacklistValidator;

@Configuration
public class JwtDecoderConfig {

    @Bean
    public JwtDecoder jwtDecoder(
            SigningKeyService signingKeyService,
            JwtBlacklistValidator jwtBlacklistValidator,
            JwtProperties jwtProperties) {

        JWKSource<SecurityContext> jwkSource = (jwkSelector, context) -> jwkSelector.select(signingKeyService.getJwkSet());

        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(
                JWSAlgorithm.RS256,
                jwkSource
        );
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
        });

        NimbusJwtDecoder jwtDecoder = new NimbusJwtDecoder(jwtProcessor);

        OAuth2TokenValidator<Jwt> defaultValidator = JwtValidators.createDefaultWithIssuer(jwtProperties.issuer());
        OAuth2TokenValidator<Jwt> delegatingValidator = new DelegatingOAuth2TokenValidator<>(defaultValidator, jwtBlacklistValidator);

        jwtDecoder.setJwtValidator(delegatingValidator);

        return jwtDecoder;
    }
}
