package com.vaultix.authorization.validation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Documented
@Constraint(validatedBy = StrongPasswordValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface StrongPassword {

    int MIN_LENGTH = 8;
    int MAX_LENGTH = 128;

    String message() default "Password must be between 8 and 128 characters and include uppercase, lowercase, digit, and special character without spaces";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
