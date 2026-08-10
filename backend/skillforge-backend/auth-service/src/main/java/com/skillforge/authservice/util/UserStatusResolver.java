package com.skillforge.authservice.util;

import com.skillforge.authservice.exception.EmailNotVerifiedException;
import com.skillforge.common.enums.Role;
import com.skillforge.common.enums.UserStatus;
import org.springframework.stereotype.Component;

@Component
public class UserStatusResolver {

    /**
     * Determines the initial status of a newly registered user.
     */
    public UserStatus resolveInitialStatus(Role role) {

        return switch (role) {

            case ROLE_LEARNER ->
                    UserStatus.PENDING_VERIFICATION;

            case ROLE_INSTRUCTOR ->
                    UserStatus.PENDING_VERIFICATION;

            case ROLE_ADMIN ->
                    UserStatus.ACTIVE;

            case ROLE_SUPER_ADMIN ->
                    UserStatus.ACTIVE;

            default ->
                    throw new IllegalArgumentException("Invalid role");

        };
    }

    public void validateLoginStatus(UserStatus status) {

        switch (status) {

            case ACTIVE -> {
                // Login Allowed
            }

            case PENDING_VERIFICATION ->
                    throw new EmailNotVerifiedException(
                            "Please verify your email first."
                    );


            case INACTIVE ->
                    throw new RuntimeException(
                            "Your account is inactive."
                    );

            case SUSPENDED ->
                    throw new RuntimeException(
                            "Your account has been suspended."
                    );

            case DELETED ->
                    throw new RuntimeException(
                            "Account no longer exists."
                    );
        }
    }
}