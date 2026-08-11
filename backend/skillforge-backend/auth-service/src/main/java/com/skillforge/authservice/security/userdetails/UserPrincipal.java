package com.skillforge.authservice.security.userdetails;

import com.skillforge.authservice.entity.User;

import lombok.Getter;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Getter
public class UserPrincipal implements UserDetails {

    private final UUID id;

    private final String email;

    private final String password;

    private final boolean enabled;

    private final boolean accountNonLocked;

    private final Collection<? extends GrantedAuthority> authorities;


    public UserPrincipal(User user) {

        this.id = user.getId();

        this.email = user.getEmail();

        this.password = user.getPassword();

        this.enabled = user.getEnabled();

        this.accountNonLocked = user.getAccountNonLocked();

        this.authorities = List.of(
                new SimpleGrantedAuthority(
                        user.getRole().name()
                )
        );
    }


    // =========================================================
    // USERNAME
    // =========================================================

    @Override
    public String getUsername() {
        return email;
    }


    // =========================================================
    // PASSWORD
    // =========================================================

    @Override
    public String getPassword() {
        return password;
    }


    // =========================================================
    // AUTHORITIES / ROLE
    // =========================================================

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }


    // =========================================================
    // ACCOUNT STATUS
    // =========================================================

    @Override
    public boolean isEnabled() {
        return enabled;
    }


    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }


    @Override
    public boolean isAccountNonExpired() {
        return true;
    }


    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
}