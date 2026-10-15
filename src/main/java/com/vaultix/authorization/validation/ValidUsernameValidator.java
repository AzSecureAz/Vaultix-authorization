package com.vaultix.authorization.validation;

import java.util.regex.Pattern;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class ValidUsernameValidator implements ConstraintValidator<ValidUsername, String> {

    private static final Pattern USERNAME_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9][a-zA-Z0-9_.-]{"
            + (ValidUsername.MIN_LENGTH - 2) + "," + (ValidUsername.MAX_LENGTH - 2)
            + "}[a-zA-Z0-9]$"
    );

    @Override
    public boolean isValid(String username, ConstraintValidatorContext context) {
        if (username == null) {
            return false;
        }
        return USERNAME_PATTERN.matcher(username).matches();
    }
}
