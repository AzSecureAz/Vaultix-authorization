package com.vaultix.authorization.specification;

import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.data.jpa.domain.Specification;

import com.vaultix.authorization.entity.Permission;
import com.vaultix.authorization.entity.Role;
import com.vaultix.authorization.entity.enums.RoleStatus;
import com.vaultix.authorization.specification.request.RoleSearchRequest;
import com.vaultix.common.util.UuidUtils;

import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;

public final class RoleSpecification {

    private RoleSpecification() {
    }

    public static Specification<Role> withFilters(RoleSearchRequest criteria) {
        if (criteria == null) {
            return (root, query, cb) -> cb.conjunction();
        }

        Specification<Role> spec = (root, query, cb) -> cb.conjunction();

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

        if (criteria.minLevel() != null) {
            spec = spec.and(minLevel(criteria.minLevel()));
        }

        if (criteria.maxLevel() != null) {
            spec = spec.and(maxLevel(criteria.maxLevel()));
        }

        if (criteria.permissions() != null && !criteria.permissions().isEmpty()) {
            spec = spec.and(hasPermissions(criteria.permissions()));
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

    public static Specification<Role> hasSearch(String search) {
        return (root, query, cb) -> {
            if (search == null || search.isBlank()) {
                return cb.conjunction();
            }

            String cleanSearch = search.strip().toUpperCase(Locale.ROOT);
            String pattern = "%" + cleanSearch + "%";

            Predicate namePredicate = cb.like(cb.upper(root.get("name")), pattern);

            if (!UuidUtils.isPotentialUuid(cleanSearch)) {
                return namePredicate;
            }

            Optional<UUID> uuid = UuidUtils.parseUuid(cleanSearch);
            if (uuid.isPresent()) {
                return cb.or(namePredicate, cb.equal(root.get("id"), uuid.get()));
            }

            Expression<String> idAsText = cb.function("concat", String.class, root.get("id"), cb.literal(""));
            String idPattern = "%" + search.strip().toLowerCase(Locale.ROOT) + "%";
            Predicate idPredicate = cb.like(idAsText, idPattern);
            return cb.or(namePredicate, idPredicate);
        };
    }

    public static Specification<Role> hasIds(Set<UUID> ids) {
        return (root, query, cb) -> {
            if (ids == null || ids.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("id").in(ids);
        };
    }

    public static Specification<Role> hasNames(Set<String> names) {
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

    public static Specification<Role> hasStatuses(Set<RoleStatus> statuses) {
        return (root, query, cb) -> {
            if (statuses == null || statuses.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("status").in(statuses);
        };
    }

    public static Specification<Role> minLevel(Integer minLevel) {
        return (root, query, cb) -> {
            if (minLevel == null) {
                return cb.conjunction();
            }
            return cb.greaterThanOrEqualTo(root.get("level"), minLevel);
        };
    }

    public static Specification<Role> maxLevel(Integer maxLevel) {
        return (root, query, cb) -> {
            if (maxLevel == null) {
                return cb.conjunction();
            }
            return cb.lessThanOrEqualTo(root.get("level"), maxLevel);
        };
    }

    public static Specification<Role> hasPermissions(Set<String> permissions) {
        return (root, query, cb) -> {
            if (permissions == null || permissions.isEmpty()) {
                return cb.conjunction();
            }

            Set<String> cleanNames = permissions.stream()
                    .filter(name -> name != null && !name.isBlank())
                    .map(name -> name.strip().toLowerCase(Locale.ROOT))
                    .collect(Collectors.toSet());

            if (cleanNames.isEmpty()) {
                return cb.conjunction();
            }

            if (query != null) {
                query.distinct(true);
            }

            Join<Role, Permission> permJoin = root.join("permissions", JoinType.INNER);
            return cb.lower(permJoin.get("name")).in(cleanNames);
        };
    }

    public static Specification<Role> createdAfter(Instant after) {
        return (root, query, cb) -> {
            if (after == null) {
                return cb.conjunction();
            }
            return cb.greaterThanOrEqualTo(root.get("createdAt"), after);
        };
    }

    public static Specification<Role> createdBefore(Instant before) {
        return (root, query, cb) -> {
            if (before == null) {
                return cb.conjunction();
            }
            return cb.lessThanOrEqualTo(root.get("createdAt"), before);
        };
    }

    public static Specification<Role> createdBy(Set<UUID> createdBy) {
        return (root, query, cb) -> {
            if (createdBy == null || createdBy.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("createdBy").in(createdBy);
        };
    }

    public static Specification<Role> updatedAfter(Instant after) {
        return (root, query, cb) -> {
            if (after == null) {
                return cb.conjunction();
            }
            return cb.greaterThanOrEqualTo(root.get("updatedAt"), after);
        };
    }

    public static Specification<Role> updatedBefore(Instant before) {
        return (root, query, cb) -> {
            if (before == null) {
                return cb.conjunction();
            }
            return cb.lessThanOrEqualTo(root.get("updatedAt"), before);
        };
    }

    public static Specification<Role> updatedBy(Set<UUID> updatedBy) {
        return (root, query, cb) -> {
            if (updatedBy == null || updatedBy.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("updatedBy").in(updatedBy);
        };
    }
}
