package com.vaultix.authorization.validation;

import java.util.Locale;
import java.util.regex.Pattern;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class ValidRoleNameValidator implements ConstraintValidator<ValidRoleName, String> {

    private static final String ROLE_PREFIX = "ROLE_";

    private static final Pattern BASE_ROLE_PATTERN = Pattern.compile(
            "^(?!.*__)[a-zA-Z][a-zA-Z0-9_]{"
            + (ValidRoleName.MIN_LENGTH - 2) + "," + (ValidRoleName.MAX_BASE_LENGTH - 2)
            + "}[a-zA-Z0-9]$"
    );

    @Override
    public boolean isValid(String roleName, ConstraintValidatorContext context) {
        if (roleName == null || roleName.isBlank()) {
            return false;
        }

        String stripped = roleName.strip();
        String upper = stripped.toUpperCase(Locale.ROOT);
        String baseName = upper.startsWith(ROLE_PREFIX)
                ? upper.substring(ValidRoleName.PREFIX_LENGTH)
                : upper;

        return BASE_ROLE_PATTERN.matcher(baseName).matches();
    }
}
