package com.vaultix.authorization.validation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Documented
@Constraint(validatedBy = ValidUsernameValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidUsername {

    int MIN_LENGTH = 3;
    int MAX_LENGTH = 128;

    String message() default "Username must start and end with an alphanumeric character, contain only letters, numbers, underscores, dots, or hyphens, and be between 3 and 128 characters";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
