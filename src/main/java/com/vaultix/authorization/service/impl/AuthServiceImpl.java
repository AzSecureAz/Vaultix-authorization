package com.vaultix.authorization.service.impl;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.service.AuthService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;

    @Override
    public String login(LoginRequest request) {
        log.info("Attempting authentication for identifier: {}", request.identifier());

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.identifier(), request.password())
        );

        Object principal = authentication.getPrincipal();
        log.info("Authentication successful for: {}", authentication.getName());

        return principal.toString();
    }
}
