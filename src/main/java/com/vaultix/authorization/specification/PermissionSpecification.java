package com.vaultix.authorization.specification;

import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.data.jpa.domain.Specification;

import com.vaultix.authorization.entity.Permission;
import com.vaultix.authorization.entity.enums.PermissionStatus;
import com.vaultix.authorization.specification.request.PermissionSearchRequest;
import com.vaultix.common.util.UuidUtils;

import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Predicate;

public final class PermissionSpecification {

    private PermissionSpecification() {
    }

    public static Specification<Permission> withFilters(PermissionSearchRequest criteria) {
        if (criteria == null) {
            return (root, query, cb) -> cb.conjunction();
        }

        Specification<Permission> spec = (root, query, cb) -> cb.conjunction();

        if (criteria.search() != null && !criteria.search().isBlank()) {
            spec = spec.and(hasSearch(criteria.search().strip()));
        }

        if (criteria.ids() != null && !criteria.ids().isEmpty()) {
            spec = spec.and(hasIds(criteria.ids()));
        }

        if (criteria.names() != null && !criteria.names().isEmpty()) {
            spec = spec.and(hasNames(criteria.names()));
        }

        if (criteria.statuses() != null && !criteria.statuses().isEmpty()) {
            spec = spec.and(hasStatuses(criteria.statuses()));
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

    public static Specification<Permission> hasSearch(String search) {
        return (root, query, cb) -> {
            if (search == null || search.isBlank()) {
                return cb.conjunction();
            }

            String cleanSearch = search.strip().toLowerCase();
            String pattern = "%" + cleanSearch + "%";

            Predicate namePredicate = cb.like(cb.lower(root.get("name")), pattern);

            if (!UuidUtils.isPotentialUuid(cleanSearch)) {
                return namePredicate;
            }

            Optional<UUID> uuid = UuidUtils.parseUuid(cleanSearch);
            if (uuid.isPresent()) {
                return cb.or(namePredicate, cb.equal(root.get("id"), uuid.get()));
            }

            Expression<String> idAsText = cb.function("concat", String.class, root.get("id"), cb.literal(""));
            Predicate idPredicate = cb.like(idAsText, pattern);
            return cb.or(namePredicate, idPredicate);
        };
    }

    public static Specification<Permission> hasIds(Set<UUID> ids) {
        return (root, query, cb) -> {
            if (ids == null || ids.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("id").in(ids);
        };
    }

    public static Specification<Permission> hasNames(Set<String> names) {
        return (root, query, cb) -> {
            if (names == null || names.isEmpty()) {
                return cb.conjunction();
            }

            Set<String> cleanNames = names.stream()
                    .filter(name -> name != null && !name.isBlank())
                    .map(name -> name.strip().toUpperCase(Locale.ROOT))
                    .collect(Collectors.toSet());

            if (cleanNames.isEmpty()) {
                return cb.conjunction();
            }

            return cb.upper(root.get("name")).in(cleanNames);
        };
    }

    public static Specification<Permission> hasStatuses(Set<PermissionStatus> statuses) {
        return (root, query, cb) -> {
            if (statuses == null || statuses.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("status").in(statuses);
        };
    }

    public static Specification<Permission> updatedAfter(Instant after) {
        return (root, query, cb) -> {
            if (after == null) {
                return cb.conjunction();
            }
            return cb.greaterThanOrEqualTo(root.get("updatedAt"), after);
        };
    }

    public static Specification<Permission> updatedBefore(Instant before) {
        return (root, query, cb) -> {
            if (before == null) {
                return cb.conjunction();
            }
            return cb.lessThanOrEqualTo(root.get("updatedAt"), before);
        };
    }

    public static Specification<Permission> updatedBy(Set<UUID> updatedBy) {
        return (root, query, cb) -> {
            if (updatedBy == null || updatedBy.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("updatedBy").in(updatedBy);
        };
    }
}
