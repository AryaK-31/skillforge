package com.skillforge.common.constants;

public final class SecurityConstants {

    private SecurityConstants() {}

    public static final String TOKEN_PREFIX = "Bearer ";

    public static final String HEADER = "Authorization";

    public static final String ROLE_PREFIX = "ROLE_";

    public static final long ACCESS_TOKEN_EXPIRY = 15 * 60 * 1000;

    public static final long REFRESH_TOKEN_EXPIRY = 7L * 24 * 60 * 60 * 1000;
}
