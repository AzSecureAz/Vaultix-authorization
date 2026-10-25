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
import com.vaultix.common.security.PermissionRevocationService;
import com.vaultix.common.security.RedisPermissionRevocationService;
import com.vaultix.common.security.RedisRoleRevocationService;
import com.vaultix.common.security.RedisSudoService;
import com.vaultix.common.security.RedisTokenBlacklistService;
import com.vaultix.common.security.RequireSudoAspect;
import com.vaultix.common.security.RoleRevocationService;
import com.vaultix.common.security.SudoService;
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
        return RedisTokenBlacklistService.builder()
                .stringRedisTemplate(stringRedisTemplate)
                .build();
    }

    @Bean
    public PermissionRevocationService permissionRevocationService(StringRedisTemplate stringRedisTemplate) {
        return RedisPermissionRevocationService.builder()
                .stringRedisTemplate(stringRedisTemplate)
                .build();
    }

    @Bean
    public RoleRevocationService roleRevocationService(StringRedisTemplate stringRedisTemplate) {
        return RedisRoleRevocationService.builder()
                .stringRedisTemplate(stringRedisTemplate)
                .build();
    }

    @Bean
    public CustomJwtAuthenticationConverter customJwtAuthenticationConverter(
            RoleRevocationService roleRevocationService,
            PermissionRevocationService permissionRevocationService) {
        return CustomJwtAuthenticationConverter.builder()
                .roleRevocationService(roleRevocationService)
                .permissionRevocationService(permissionRevocationService)
                .build();
    }

    @Bean
    public CustomAuthenticationEntryPoint customAuthenticationEntryPoint(ObjectMapper objectMapper) {
        return CustomAuthenticationEntryPoint.builder()
                .objectMapper(objectMapper)
                .build();
    }

    @Bean
    public CustomAccessDeniedHandler customAccessDeniedHandler(ObjectMapper objectMapper) {
        return CustomAccessDeniedHandler.builder()
                .objectMapper(objectMapper)
                .build();
    }

    @Bean
    public JwtBlacklistValidator jwtBlacklistValidator(TokenBlacklistService tokenBlacklistService) {
        return JwtBlacklistValidator.builder()
                .tokenBlacklistService(tokenBlacklistService)
                .build();
    }

    @Bean
    public SudoService sudoService(StringRedisTemplate stringRedisTemplate) {
        return RedisSudoService.builder()
                .stringRedisTemplate(stringRedisTemplate)
                .build();
    }

    @Bean
    public RequireSudoAspect requireSudoAspect(SudoService sudoService) {
        return RequireSudoAspect.builder()
                .sudoService(sudoService)
                .build();
    }
}
