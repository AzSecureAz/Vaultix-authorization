package com.vaultix.authorization.validation;

import java.util.regex.Pattern;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class ValidPasskeyLabelValidator implements ConstraintValidator<ValidPasskeyLabel, String> {

    /*
     * Regex rules for passkey label:
     * - Length: 1 to 128 characters
     * - Disallows consecutive spaces: (?!.* {2})
     * - Single char: must be Unicode letter or digit
     * - Multi char: starts with letter/digit, ends with letter/digit or closing paren/dot/plus
     * - Allowed middle characters: letters, digits, spaces, -, _, (, ), ., ', ,, /, +, #, :, @
     */
    public static final Pattern PASSKEY_LABEL_PATTERN = Pattern.compile(
            "^(?!.* {2})[\\p{L}\\p{N}](?:[\\p{L}\\p{N} \\-_().',/+#:@]{0,"
            + (ValidPasskeyLabel.MAX_LENGTH - 2)
            + "}[\\p{L}\\p{N}.)+])?$"
    );

    @Override
    public boolean isValid(String label, ConstraintValidatorContext context) {
        return isValid(label);
    }

    public static boolean isValid(String label) {
        if (label == null || label.isBlank()) {
            return false;
        }
        String stripped = label.strip();
        if (stripped.length() < ValidPasskeyLabel.MIN_LENGTH || stripped.length() > ValidPasskeyLabel.MAX_LENGTH) {
            return false;
        }
        return PASSKEY_LABEL_PATTERN.matcher(stripped).matches();
    }

    public static String sanitizeOrDefault(String rawLabel, String defaultLabel) {
        if (rawLabel == null || rawLabel.isBlank()) {
            return defaultLabel;
        }
        String stripped = rawLabel.strip();
        if (isValid(stripped)) {
            return stripped;
        }
        return defaultLabel;
    }
}
