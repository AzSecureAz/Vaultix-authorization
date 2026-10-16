package com.vaultix.authorization.controller;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.service.SigningKeyService;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class JwksController {

    private final SigningKeyService signingKeyService;

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getJwks() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(15, TimeUnit.MINUTES).cachePublic())
                .body(signingKeyService.getJwkSetAsMap());
    }
}
