package com.vaultix.authorization.scheduler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.vaultix.authorization.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

@Slf4j
@Component
@RequiredArgsConstructor
public class UserScheduler {

    private final UserService userService;

    @Scheduled(cron = "${vaultix.security.user.cleanup-cron:0 40 2 * * ?}")
    @SchedulerLock(name = "userCleanup", lockAtMostFor = "15m", lockAtLeastFor = "5m")
    public void scheduleUserCleanup() {
        log.info("Triggering scheduled deleted users cleanup...");
        userService.cleanSoftDeletedUsers();
    }
}
