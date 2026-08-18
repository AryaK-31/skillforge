package com.skillforge.authservice.util;

import com.skillforge.common.enums.Role;
import org.springframework.stereotype.Component;

@Component
public class RoleResolver {

    /**
     * Determines the role assigned during registration.
     */
    public Role resolveRole(Role requestedRole) {

        // If no role is provided, register as Learner
        if (requestedRole == null) {
            return Role.ROLE_LEARNER;
        }

        return switch (requestedRole) {

            case ROLE_LEARNER ->
                    Role.ROLE_LEARNER;

            case ROLE_INSTRUCTOR ->
                    Role.ROLE_INSTRUCTOR;

            case ROLE_ADMIN,
                 ROLE_SUPER_ADMIN ->
                    throw new IllegalArgumentException(
                            "Registration is not allowed for this role."
                    );
        };
    }
}