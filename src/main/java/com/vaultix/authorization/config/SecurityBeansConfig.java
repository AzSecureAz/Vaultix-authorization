package com.vaultix.authorization.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.vaultix.common.security.CustomAccessDeniedHandler;
import com.vaultix.common.security.CustomAuthenticationEntryPoint;
import com.vaultix.common.security.CustomJwtAuthenticationConverter;
import com.vaultix.common.security.JwtBlacklistValidator;
import com.vaultix.common.security.RedisTokenBlacklistService;
import com.vaultix.common.security.TokenBlacklistService;

import tools.jackson.databind.ObjectMapper;

@Configuration
public class SecurityBeansConfig {

    private static final String DEFAULT_ENCODING_ID = "argon2";

    @Bean
    public PasswordEncoder passwordEncoder() {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put(DEFAULT_ENCODING_ID, Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8());

        return new DelegatingPasswordEncoder(DEFAULT_ENCODING_ID, encoders);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public TokenBlacklistService tokenBlacklistService(StringRedisTemplate stringRedisTemplate) {
        return new RedisTokenBlacklistService(stringRedisTemplate);
    }

    @Bean
    public CustomJwtAuthenticationConverter customJwtAuthenticationConverter() {
        return new CustomJwtAuthenticationConverter();
    }

    @Bean
    public CustomAuthenticationEntryPoint customAuthenticationEntryPoint(ObjectMapper objectMapper) {
        return new CustomAuthenticationEntryPoint(objectMapper);
    }

    @Bean
    public CustomAccessDeniedHandler customAccessDeniedHandler(ObjectMapper objectMapper) {
        return new CustomAccessDeniedHandler(objectMapper);
    }

    @Bean
    public JwtBlacklistValidator jwtBlacklistValidator(TokenBlacklistService tokenBlacklistService) {
        return new JwtBlacklistValidator(tokenBlacklistService);
    }
}
