package com.vaultix.authorization.specification;

import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.data.jpa.domain.Specification;

import com.vaultix.authorization.entity.Role;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.specification.request.UserSearchRequest;
import com.vaultix.common.util.UuidUtils;

import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;

public final class UserSpecification {

    private UserSpecification() {
    }

    public static Specification<User> withFilters(UserSearchRequest criteria) {
        if (criteria == null) {
            return (root, query, cb) -> cb.conjunction();
        }

        Specification<User> spec = (root, query, cb) -> cb.conjunction();

        if (criteria.search() != null && !criteria.search().isBlank()) {
            spec = spec.and(hasSearch(criteria.search().strip()));
        }

        if (criteria.ids() != null && !criteria.ids().isEmpty()) {
            spec = spec.and(hasIds(criteria.ids()));
        }

        if (criteria.usernames() != null && !criteria.usernames().isEmpty()) {
            spec = spec.and(hasUsernames(criteria.usernames()));
        }

        if (criteria.emails() != null && !criteria.emails().isEmpty()) {
            spec = spec.and(hasEmails(criteria.emails()));
        }

        if (criteria.phoneNumbers() != null && !criteria.phoneNumbers().isEmpty()) {
            spec = spec.and(hasPhoneNumbers(criteria.phoneNumbers()));
        }

        if (criteria.statuses() != null && !criteria.statuses().isEmpty()) {
            spec = spec.and(hasStatuses(criteria.statuses()));
        }

        if (criteria.roles() != null && !criteria.roles().isEmpty()) {
            spec = spec.and(hasRoles(criteria.roles()));
        }

        if (criteria.emailVerified() != null) {
            spec = spec.and(emailVerified(criteria.emailVerified()));
        }

        if (criteria.phoneNumberVerified() != null) {
            spec = spec.and(phoneNumberVerified(criteria.phoneNumberVerified()));
        }

        if (criteria.mfaEnabled() != null) {
            spec = spec.and(mfaEnabled(criteria.mfaEnabled()));
        }

        if (criteria.passkeyEnabled() != null) {
            spec = spec.and(passkeyEnabled(criteria.passkeyEnabled()));
        }

        if (criteria.smsMfaEnabled() != null) {
            spec = spec.and(smsMfaEnabled(criteria.smsMfaEnabled()));
        }

        if (criteria.hasSocialAccounts() != null) {
            spec = spec.and(hasSocialAccounts(criteria.hasSocialAccounts()));
        }

        if (criteria.hasPassword() != null) {
            spec = spec.and(hasPassword(criteria.hasPassword()));
        }

        if (criteria.minFailedLoginAttempts() != null) {
            spec = spec.and(minFailedLoginAttempts(criteria.minFailedLoginAttempts()));
        }

        if (criteria.maxFailedLoginAttempts() != null) {
            spec = spec.and(maxFailedLoginAttempts(criteria.maxFailedLoginAttempts()));
        }

        if (criteria.lockedUntilAfter() != null) {
            spec = spec.and(lockedUntilAfter(criteria.lockedUntilAfter()));
        }

        if (criteria.lockedUntilBefore() != null) {
            spec = spec.and(lockedUntilBefore(criteria.lockedUntilBefore()));
        }

        if (criteria.lastLoginAfter() != null) {
            spec = spec.and(lastLoginAfter(criteria.lastLoginAfter()));
        }

        if (criteria.lastLoginBefore() != null) {
            spec = spec.and(lastLoginBefore(criteria.lastLoginBefore()));
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

    public static Specification<User> hasSearch(String search) {
        return (root, query, cb) -> {
            if (search == null || search.isBlank()) {
                return cb.conjunction();
            }

            String cleanSearch = search.strip().toLowerCase(Locale.ROOT);
            String pattern = "%" + cleanSearch + "%";

            Predicate usernamePredicate = cb.like(cb.lower(root.get("username")), pattern);
            Predicate emailPredicate = cb.like(cb.lower(root.get("email")), pattern);
            Predicate fullNamePredicate = cb.like(cb.lower(root.get("fullName")), pattern);
            Predicate phonePredicate = cb.like(root.get("phoneNumber"), pattern);

            Predicate textPredicate = cb.or(usernamePredicate, emailPredicate, fullNamePredicate, phonePredicate);

            if (!UuidUtils.isPotentialUuid(cleanSearch)) {
                return textPredicate;
            }

            Optional<UUID> uuid = UuidUtils.parseUuid(cleanSearch);
            if (uuid.isPresent()) {
                return cb.or(textPredicate, cb.equal(root.get("id"), uuid.get()));
            }

            Expression<String> idAsText = cb.function("concat", String.class, root.get("id"), cb.literal(""));
            Predicate idPredicate = cb.like(idAsText, pattern);
            return cb.or(textPredicate, idPredicate);
        };
    }

    public static Specification<User> hasIds(Set<UUID> ids) {
        return (root, query, cb) -> {
            if (ids == null || ids.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("id").in(ids);
        };
    }

    public static Specification<User> hasUsernames(Set<String> usernames) {
        return (root, query, cb) -> {
            if (usernames == null || usernames.isEmpty()) {
                return cb.conjunction();
            }

            Set<String> cleanUsernames = usernames.stream()
                    .filter(username -> username != null && !username.isBlank())
                    .map(username -> username.strip().toLowerCase(Locale.ROOT))
                    .collect(Collectors.toSet());

            if (cleanUsernames.isEmpty()) {
                return cb.conjunction();
            }

            return cb.lower(root.get("username")).in(cleanUsernames);
        };
    }

    public static Specification<User> hasEmails(Set<String> emails) {
        return (root, query, cb) -> {
            if (emails == null || emails.isEmpty()) {
                return cb.conjunction();
            }

            Set<String> cleanEmails = emails.stream()
                    .filter(email -> email != null && !email.isBlank())
                    .map(email -> email.strip().toLowerCase(Locale.ROOT))
                    .collect(Collectors.toSet());

            if (cleanEmails.isEmpty()) {
                return cb.conjunction();
            }

            return cb.lower(root.get("email")).in(cleanEmails);
        };
    }

    public static Specification<User> hasPhoneNumbers(Set<String> phoneNumbers) {
        return (root, query, cb) -> {
            if (phoneNumbers == null || phoneNumbers.isEmpty()) {
                return cb.conjunction();
            }

            Set<String> cleanPhones = phoneNumbers.stream()
                    .filter(phone -> phone != null && !phone.isBlank())
                    .map(String::strip)
                    .collect(Collectors.toSet());

            if (cleanPhones.isEmpty()) {
                return cb.conjunction();
            }

            return root.get("phoneNumber").in(cleanPhones);
        };
    }

    public static Specification<User> hasStatuses(Set<UserStatus> statuses) {
        return (root, query, cb) -> {
            if (statuses == null || statuses.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("status").in(statuses);
        };
    }

    public static Specification<User> hasRoles(Set<String> roles) {
        return (root, query, cb) -> {
            if (roles == null || roles.isEmpty()) {
                return cb.conjunction();
            }

            Set<String> cleanRoles = roles.stream()
                    .filter(role -> role != null && !role.isBlank())
                    .map(role -> role.strip().toUpperCase(Locale.ROOT))
                    .collect(Collectors.toSet());

            if (cleanRoles.isEmpty()) {
                return cb.conjunction();
            }

            if (query != null) {
                query.distinct(true);
            }

            Join<User, Role> roleJoin = root.join("roles", JoinType.INNER);
            return cb.upper(roleJoin.get("name")).in(cleanRoles);
        };
    }

    public static Specification<User> emailVerified(Boolean emailVerified) {
        return (root, query, cb) -> {
            if (emailVerified == null) {
                return cb.conjunction();
            }
            return cb.equal(root.get("emailVerified"), emailVerified);
        };
    }

    public static Specification<User> phoneNumberVerified(Boolean phoneNumberVerified) {
        return (root, query, cb) -> {
            if (phoneNumberVerified == null) {
                return cb.conjunction();
            }
            return cb.equal(root.get("phoneNumberVerified"), phoneNumberVerified);
        };
    }

    public static Specification<User> mfaEnabled(Boolean mfaEnabled) {
        return (root, query, cb) -> {
            if (mfaEnabled == null) {
                return cb.conjunction();
            }
            return cb.equal(root.get("mfaEnabled"), mfaEnabled);
        };
    }

    public static Specification<User> passkeyEnabled(Boolean passkeyEnabled) {
        return (root, query, cb) -> {
            if (passkeyEnabled == null) {
                return cb.conjunction();
            }
            return cb.equal(root.get("passkeyEnabled"), passkeyEnabled);
        };
    }

    public static Specification<User> smsMfaEnabled(Boolean smsMfaEnabled) {
        return (root, query, cb) -> {
            if (smsMfaEnabled == null) {
                return cb.conjunction();
            }
            return cb.equal(root.get("smsMfaEnabled"), smsMfaEnabled);
        };
    }

    public static Specification<User> hasSocialAccounts(Boolean hasSocialAccounts) {
        return (root, query, cb) -> {
            if (hasSocialAccounts == null) {
                return cb.conjunction();
            }
            return cb.equal(root.get("hasSocialAccounts"), hasSocialAccounts);
        };
    }

    public static Specification<User> hasPassword(Boolean hasPassword) {
        return (root, query, cb) -> {
            if (hasPassword == null) {
                return cb.conjunction();
            }
            return Boolean.TRUE.equals(hasPassword)
                    ? cb.and(cb.isNotNull(root.get("passwordHash")), cb.notEqual(cb.trim(root.get("passwordHash")), ""))
                    : cb.or(cb.isNull(root.get("passwordHash")), cb.equal(cb.trim(root.get("passwordHash")), ""));
        };
    }

    public static Specification<User> minFailedLoginAttempts(Integer minAttempts) {
        return (root, query, cb) -> {
            if (minAttempts == null) {
                return cb.conjunction();
            }
            return cb.greaterThanOrEqualTo(root.get("failedLoginAttempts"), minAttempts);
        };
    }

    public static Specification<User> maxFailedLoginAttempts(Integer maxAttempts) {
        return (root, query, cb) -> {
            if (maxAttempts == null) {
                return cb.conjunction();
            }
            return cb.lessThanOrEqualTo(root.get("failedLoginAttempts"), maxAttempts);
        };
    }

    public static Specification<User> lockedUntilAfter(Instant after) {
        return (root, query, cb) -> {
            if (after == null) {
                return cb.conjunction();
            }
            return cb.greaterThanOrEqualTo(root.get("lockedUntil"), after);
        };
    }

    public static Specification<User> lockedUntilBefore(Instant before) {
        return (root, query, cb) -> {
            if (before == null) {
                return cb.conjunction();
            }
            return cb.lessThanOrEqualTo(root.get("lockedUntil"), before);
        };
    }

    public static Specification<User> lastLoginAfter(Instant after) {
        return (root, query, cb) -> {
            if (after == null) {
                return cb.conjunction();
            }
            return cb.greaterThanOrEqualTo(root.get("lastLoginAt"), after);
        };
    }

    public static Specification<User> lastLoginBefore(Instant before) {
        return (root, query, cb) -> {
            if (before == null) {
                return cb.conjunction();
            }
            return cb.lessThanOrEqualTo(root.get("lastLoginAt"), before);
        };
    }

    public static Specification<User> createdAfter(Instant after) {
        return (root, query, cb) -> {
            if (after == null) {
                return cb.conjunction();
            }
            return cb.greaterThanOrEqualTo(root.get("createdAt"), after);
        };
    }

    public static Specification<User> createdBefore(Instant before) {
        return (root, query, cb) -> {
            if (before == null) {
                return cb.conjunction();
            }
            return cb.lessThanOrEqualTo(root.get("createdAt"), before);
        };
    }

    public static Specification<User> createdBy(Set<UUID> createdBy) {
        return (root, query, cb) -> {
            if (createdBy == null || createdBy.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("createdBy").in(createdBy);
        };
    }

    public static Specification<User> updatedAfter(Instant after) {
        return (root, query, cb) -> {
            if (after == null) {
                return cb.conjunction();
            }
            return cb.greaterThanOrEqualTo(root.get("updatedAt"), after);
        };
    }

    public static Specification<User> updatedBefore(Instant before) {
        return (root, query, cb) -> {
            if (before == null) {
                return cb.conjunction();
            }
            return cb.lessThanOrEqualTo(root.get("updatedAt"), before);
        };
    }

    public static Specification<User> updatedBy(Set<UUID> updatedBy) {
        return (root, query, cb) -> {
            if (updatedBy == null || updatedBy.isEmpty()) {
                return cb.conjunction();
            }
            return root.get("updatedBy").in(updatedBy);
        };
    }
}
