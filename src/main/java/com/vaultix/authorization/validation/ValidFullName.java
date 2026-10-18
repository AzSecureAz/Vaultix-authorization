package com.vaultix.authorization.validation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Documented
@Constraint(validatedBy = ValidFullNameValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidFullName {

    int MIN_LENGTH = 2;
    int MAX_LENGTH = 256;

    String message() default "Full name must start with a letter, end with a letter or dot, contain only letters, spaces, hyphens, dots, or apostrophes without consecutive separators, and be between 2 and 256 characters";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
