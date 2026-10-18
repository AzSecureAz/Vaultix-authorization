package com.vaultix.authorization.validation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Documented
@Constraint(validatedBy = ValidPhoneNumberValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPhoneNumber {

    int MAX_LENGTH = 32;

    String defaultRegion() default "";

    String message() default "Phone number must be a valid international phone number (e.g. +14155552671, +919876543210)";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
