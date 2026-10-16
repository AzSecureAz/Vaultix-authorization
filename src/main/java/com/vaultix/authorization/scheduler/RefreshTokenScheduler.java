package com.vaultix.authorization.scheduler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.vaultix.authorization.service.TokenService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

@Slf4j
@Component
@RequiredArgsConstructor
public class RefreshTokenScheduler {

    private final TokenService tokenService;

    @Scheduled(cron = "${vaultix.security.jwt.refresh-token-cleanup-cron:0 20 2 * * ?}")
    @SchedulerLock(name = "refreshTokenCleanup", lockAtMostFor = "15m", lockAtLeastFor = "5m")
    public void scheduleRefreshTokenCleanup() {
        log.info("Triggering scheduled refresh token cleanup...");
        tokenService.cleanExpiredTokens();
    }
}
