package com.vaultix.authorization.specification;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import org.springframework.data.jpa.domain.Specification;

import com.vaultix.authorization.entity.SigningKey;
import com.vaultix.authorization.entity.enums.KeyStatus;
import com.vaultix.authorization.specification.request.SigningKeySearchRequest;

public final class SigningKeySpecification {

    private SigningKeySpecification() {
    }

    public static Specification<SigningKey> withFilters(SigningKeySearchRequest criteria) {
        if (criteria == null) {
            return (root, query, cb) -> cb.conjunction();
        }

        Specification<SigningKey> spec = (root, query, cb) -> cb.conjunction();

        if (criteria.search() != null && !criteria.search().isBlank()) {
            spec = spec.and(hasSearch(criteria.search().strip()));
        }

        if (criteria.statuses() != null && !criteria.statuses().isEmpty()) {
            spec = spec.and(hasStatuses(criteria.statuses()));
        }

        if (criteria.createdAfter() != null) {
            spec = spec.and(createdAfter(criteria.createdAfter()));
        }

        if (criteria.createdBefore() != null) {
            spec = spec.and(createdBefore(criteria.createdBefore()));
        }

        if (criteria.createdBy() != null && !criteria.createdBy().isEmpty()) {
            spec = spec.and(createdBy(criteria.createdBy()));
        }

        if (criteria.updatedAfter() != null) {
            spec = spec.and(updatedAfter(criteria.updatedAfter()));
        }

        if (criteria.updatedBefore() != null) {
            spec = spec.and(updatedBefore(criteria.updatedBefore()));
        }

        if (criteria.updatedBy() != null && !criteria.updatedBy().isEmpty()) {
            spec = spec.and(updatedBy(criteria.updatedBy()));
        }

        return spec;
    }

    public static Specification<SigningKey> hasSearch(String search) {
        return (root, query, cb) -> {
            if (search == null || search.isBlank()) {
                return cb.conjunction();
            }

            String cleanSearch = search.strip().toLowerCase();
            String pattern = "%" + cleanSearch + "%";

            return cb.like(cb.lower(root.get("kid")), pattern);
        };
    }

    public static Specification<SigningKey> hasStatuses(Set<KeyStatus> statuses) {
        return (root, query, cb) -> {
            if (statuses == null || statuses.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("status").in(statuses);
        };
    }

    public static Specification<SigningKey> createdAfter(Instant after) {
        return (root, query, cb) -> {
            if (after == null) {
                return cb.conjunction();
            }
            return cb.greaterThanOrEqualTo(root.get("createdAt"), after);
        };
    }

    public static Specification<SigningKey> createdBefore(Instant before) {
        return (root, query, cb) -> {
            if (before == null) {
                return cb.conjunction();
            }
            return cb.lessThanOrEqualTo(root.get("createdAt"), before);
        };
    }

    public static Specification<SigningKey> createdBy(Set<UUID> createdBy) {
        return (root, query, cb) -> {
            if (createdBy == null || createdBy.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("createdBy").in(createdBy);
        };
    }

    public static Specification<SigningKey> updatedAfter(Instant after) {
        return (root, query, cb) -> {
            if (after == null) {
                return cb.conjunction();
            }
            return cb.greaterThanOrEqualTo(root.get("updatedAt"), after);
        };
    }

    public static Specification<SigningKey> updatedBefore(Instant before) {
        return (root, query, cb) -> {
            if (before == null) {
                return cb.conjunction();
            }
            return cb.lessThanOrEqualTo(root.get("updatedAt"), before);
        };
    }

    public static Specification<SigningKey> updatedBy(Set<UUID> updatedBy) {
        return (root, query, cb) -> {
            if (updatedBy == null || updatedBy.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("updatedBy").in(updatedBy);
        };
    }
}
