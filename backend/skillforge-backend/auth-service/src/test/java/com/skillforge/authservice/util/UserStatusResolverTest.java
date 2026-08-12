package com.skillforge.authservice.util;

import com.skillforge.authservice.exception.EmailNotVerifiedException;
import com.skillforge.common.enums.Role;
import com.skillforge.common.enums.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UserStatusResolverTest {

    private UserStatusResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new UserStatusResolver();
    }

    @Test
    void learnerShouldStartAsPendingVerification() {
        assertThat(resolver.resolveInitialStatus(Role.ROLE_LEARNER))
                .isEqualTo(UserStatus.PENDING_VERIFICATION);
    }

    @Test
    void instructorShouldStartAsPendingVerification() {
        assertThat(resolver.resolveInitialStatus(Role.ROLE_INSTRUCTOR))
                .isEqualTo(UserStatus.PENDING_VERIFICATION);
    }

    @Test
    void adminShouldStartAsActive() {
        assertThat(resolver.resolveInitialStatus(Role.ROLE_ADMIN))
                .isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void superAdminShouldStartAsActive() {
        assertThat(resolver.resolveInitialStatus(Role.ROLE_SUPER_ADMIN))
                .isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void activeUserShouldBeAllowedToLogin() {
        resolver.validateLoginStatus(UserStatus.ACTIVE);
    }

    @Test
    void pendingUserShouldBeRejected() {
        assertThatThrownBy(() -> resolver.validateLoginStatus(UserStatus.PENDING_VERIFICATION))
                .isInstanceOf(EmailNotVerifiedException.class)
                .hasMessage("Please verify your email first.");
    }

    @Test
    void inactiveUserShouldBeRejected() {
        assertThatThrownBy(() -> resolver.validateLoginStatus(UserStatus.INACTIVE))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Your account is inactive.");
    }

    @Test
    void suspendedUserShouldBeRejected() {
        assertThatThrownBy(() -> resolver.validateLoginStatus(UserStatus.SUSPENDED))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Your account has been suspended.");
    }

    @Test
    void deletedUserShouldBeRejected() {
        assertThatThrownBy(() -> resolver.validateLoginStatus(UserStatus.DELETED))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Account no longer exists.");
    }
}
