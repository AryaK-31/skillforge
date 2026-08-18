CREATE TABLE users
(
    id UUID PRIMARY KEY,

    first_name VARCHAR(50) NOT NULL,

    last_name VARCHAR(50) NOT NULL,

    email VARCHAR(100) NOT NULL UNIQUE,

    password VARCHAR(255) NOT NULL,

    role VARCHAR(30) NOT NULL,

    status VARCHAR(30) NOT NULL,

    email_verified BOOLEAN NOT NULL,

    enabled BOOLEAN NOT NULL,

    account_non_locked BOOLEAN NOT NULL,

    created_at TIMESTAMP NOT NULL,

    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE refresh_tokens
(
    id UUID PRIMARY KEY,

    token VARCHAR(255) NOT NULL UNIQUE,

    expiry_date TIMESTAMP NOT NULL,

    user_id UUID NOT NULL UNIQUE,

    created_at TIMESTAMP NOT NULL,

    updated_at TIMESTAMP NOT NULL,

    CONSTRAINT fk_refresh_token_user
        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
);