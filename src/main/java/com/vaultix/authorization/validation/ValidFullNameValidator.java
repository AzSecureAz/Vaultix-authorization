package com.vaultix.authorization.validation;

import java.util.regex.Pattern;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class ValidFullNameValidator implements ConstraintValidator<ValidFullName, String> {

    private static final Pattern FULL_NAME_PATTERN = Pattern.compile(
            "^(?!.* {2})(?!.*[-'] )(?!.* [-'])(?!.* \\.)(?!.*--)(?!.*'')(?!.*\\.{2})\\p{L}[\\p{L} '-.]{"
            + (ValidFullName.MIN_LENGTH - 2) + "," + (ValidFullName.MAX_LENGTH - 2)
            + "}[\\p{L}.]$"
    );

    @Override
    public boolean isValid(String fullName, ConstraintValidatorContext context) {
        if (fullName == null) {
            return true;
        }
        if (fullName.isBlank()) {
            return false;
        }
        return FULL_NAME_PATTERN.matcher(fullName.strip()).matches();
    }
}
