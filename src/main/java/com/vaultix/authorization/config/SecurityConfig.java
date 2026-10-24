package com.vaultix.authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsFilter;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.security.web.webauthn.management.Webauthn4JRelyingPartyOperations;

import com.vaultix.authorization.config.properties.PasskeyProperties;
import com.vaultix.authorization.security.webauthn.RedisPublicKeyCredentialCreationOptionsRepository;
import com.vaultix.authorization.security.webauthn.RedisPublicKeyCredentialRequestOptionsRepository;
import com.vaultix.authorization.security.webauthn.WebAuthnAuthenticationFailureHandler;
import com.vaultix.authorization.security.webauthn.WebAuthnAuthenticationSuccessHandler;
import com.vaultix.common.security.CustomAccessDeniedHandler;
import com.vaultix.common.security.CustomAuthenticationEntryPoint;
import com.vaultix.common.security.CustomJwtAuthenticationConverter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomJwtAuthenticationConverter customJwtAuthenticationConverter;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final PasskeyProperties passkeyProperties;
    private final RedisPublicKeyCredentialCreationOptionsRepository creationOptionsRepository;
    private final RedisPublicKeyCredentialRequestOptionsRepository requestOptionsRepository;
    private final WebAuthnAuthenticationSuccessHandler webAuthnAuthenticationSuccessHandler;
    private final WebAuthnAuthenticationFailureHandler webAuthnAuthenticationFailureHandler;

    @Bean
    public WebAuthnRelyingPartyOperations webAuthnRelyingPartyOperations(
            PublicKeyCredentialUserEntityRepository userEntityRepository,
            UserCredentialRepository userCredentialRepository) {
        PublicKeyCredentialRpEntity rpEntity = PublicKeyCredentialRpEntity.builder()
                .id(passkeyProperties.rpId())
                .name(passkeyProperties.rpName() != null ? passkeyProperties.rpName() : passkeyProperties.rpId())
                .build();
        return new Webauthn4JRelyingPartyOperations(
                userEntityRepository,
                userCredentialRepository,
                rpEntity,
                passkeyProperties.allowedOrigins()
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            WebAuthnRelyingPartyOperations webAuthnRelyingPartyOperations) throws Exception {
        PublicKeyCredentialRequestOptionsFilter requestOptionsFilter
                = new PublicKeyCredentialRequestOptionsFilter(webAuthnRelyingPartyOperations);
        requestOptionsFilter.setRequestOptionsRepository(requestOptionsRepository);

        return http
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/public/**", "/.well-known/**", "/error").permitAll()
                        .requestMatchers("/webauthn/authenticate/options", "/login/webauthn").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(customJwtAuthenticationConverter))
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler)
                )
                .addFilterBefore(requestOptionsFilter, BasicAuthenticationFilter.class)
                .webAuthn(webAuthn -> webAuthn
                        .rpId(passkeyProperties.rpId())
                        .rpName(passkeyProperties.rpName())
                        .allowedOrigins(passkeyProperties.allowedOrigins())
                        .creationOptionsRepository(creationOptionsRepository)
                        .disableDefaultRegistrationPage(true)
                        .withObjectPostProcessor(new ObjectPostProcessor<WebAuthnAuthenticationFilter>() {
                            @Override
                            public <O extends WebAuthnAuthenticationFilter> O postProcess(O filter) {
                                filter.setRequestOptionsRepository(requestOptionsRepository);
                                filter.setAuthenticationSuccessHandler(webAuthnAuthenticationSuccessHandler);
                                filter.setAuthenticationFailureHandler(webAuthnAuthenticationFailureHandler);
                                return filter;
                            }
                        })
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler)
                )
                .build();
    }
}
