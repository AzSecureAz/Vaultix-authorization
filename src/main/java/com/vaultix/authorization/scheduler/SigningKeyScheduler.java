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
public class SigningKeyScheduler {

    private final SigningKeyService signingKeyService;

    @Scheduled(cron = "${vaultix.security.jwt.key-rotation-cron:0 0 2 * * ?}")
    @SchedulerLock(name = "signingKeyRotation", lockAtMostFor = "15m", lockAtLeastFor = "5m")
    public void scheduleKeyRotation() {
        log.info("Triggering scheduled signing key rotation...");
        signingKeyService.rotateKey();
    }

    @Scheduled(cron = "${vaultix.security.jwt.key-cleanup-cron:0 10 2 * * ?}")
    @SchedulerLock(name = "signingKeyCleanup", lockAtMostFor = "15m", lockAtLeastFor = "5m")
    public void scheduleKeyCleanup() {
        log.info("Triggering scheduled signing key cleanup...");
        signingKeyService.cleanExpiredKeys();
    }
}
