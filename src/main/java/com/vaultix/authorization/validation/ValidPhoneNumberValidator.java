package com.vaultix.authorization.validation;

import java.util.Locale;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class ValidPhoneNumberValidator implements ConstraintValidator<ValidPhoneNumber, String> {

    private static final String UNKNOWN_REGION = "ZZ";
    private final PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();
    private String defaultRegion;

    @Override
    public void initialize(ValidPhoneNumber constraintAnnotation) {
        String region = constraintAnnotation.defaultRegion();
        this.defaultRegion = (region != null && !region.isBlank())
                ? region.strip().toUpperCase(Locale.ROOT)
                : UNKNOWN_REGION;
    }

    @Override
    public boolean isValid(String phoneNumber, ConstraintValidatorContext context) {
        if (phoneNumber == null) {
            return true;
        }

        if (phoneNumber.isBlank()) {
            return false;
        }

        String stripped = phoneNumber.strip();
        if (stripped.length() > ValidPhoneNumber.MAX_LENGTH) {
            return false;
        }

        try {
            PhoneNumber parsed = phoneUtil.parse(stripped, defaultRegion);
            return phoneUtil.isValidNumber(parsed);
        } catch (NumberParseException e) {
            return false;
        }
    }
}
