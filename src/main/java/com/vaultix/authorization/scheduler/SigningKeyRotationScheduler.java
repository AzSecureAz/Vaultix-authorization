package com.vaultix.authorization.scheduler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.vaultix.authorization.service.SigningKeyService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

@Slf4j
@Component
@RequiredArgsConstructor
public class SigningKeyRotationScheduler {

    private final SigningKeyService signingKeyService;

    @Scheduled(cron = "${vaultix.security.jwt.key-rotation-cron:0 * * * * ?}")
    @SchedulerLock(name = "signingKeyRotation", lockAtMostFor = "50s", lockAtLeastFor = "10s")
    public void scheduleKeyRotation() {
        log.info("Triggering scheduled signing key rotation...");
        signingKeyService.rotateKey();
    }
}
