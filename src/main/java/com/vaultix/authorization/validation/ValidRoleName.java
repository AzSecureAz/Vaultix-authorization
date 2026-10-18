package com.vaultix.authorization.validation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Documented
@Constraint(validatedBy = ValidRoleNameValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidRoleName {

    int MIN_LENGTH = 2;
    int MAX_LENGTH = 64;
    int PREFIX_LENGTH = 5;
    int MAX_BASE_LENGTH = MAX_LENGTH - PREFIX_LENGTH;

    String message() default "Role name must start with a letter, end with an alphanumeric character, contain only letters, numbers, and single underscores, and be between 2 and 59 characters without 'ROLE_' prefix (or 7 and 64 characters with 'ROLE_' prefix)";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
