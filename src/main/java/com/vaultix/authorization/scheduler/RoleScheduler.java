package com.vaultix.authorization.scheduler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.vaultix.authorization.service.RoleService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

@Slf4j
@Component
@RequiredArgsConstructor
public class RoleScheduler {

    private final RoleService roleService;

    @Scheduled(cron = "${vaultix.security.role.cleanup-cron:0 30 2 * * ?}")
    @SchedulerLock(name = "roleCleanup", lockAtMostFor = "15m", lockAtLeastFor = "5m")
    public void scheduleRoleCleanup() {
        log.info("Triggering scheduled deleted roles cleanup...");
        roleService.cleanSoftDeletedRoles();
    }
}
