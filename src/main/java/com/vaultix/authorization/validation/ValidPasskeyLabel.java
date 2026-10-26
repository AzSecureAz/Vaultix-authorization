package com.vaultix.authorization.validation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Documented
@Constraint(validatedBy = ValidPasskeyLabelValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPasskeyLabel {

    int MIN_LENGTH = 1;
    int MAX_LENGTH = 128;

    String message() default "Passkey label must be between 1 and 128 characters, start and end with an alphanumeric character (or closing parenthesis/dot/plus), and contain only letters, numbers, spaces, and safe punctuation (- _ . ' , / + # : @) without consecutive spaces";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
