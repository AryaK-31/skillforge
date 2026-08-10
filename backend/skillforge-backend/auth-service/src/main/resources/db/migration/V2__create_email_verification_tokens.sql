CREATE TABLE email_verification_tokens
(
    id UUID PRIMARY KEY,

    token VARCHAR(255) NOT NULL UNIQUE,

    expiry_date TIMESTAMP NOT NULL,

    used BOOLEAN NOT NULL DEFAULT FALSE,

    user_id UUID NOT NULL UNIQUE,

    created_at TIMESTAMP NOT NULL,

    updated_at TIMESTAMP NOT NULL,

    CONSTRAINT fk_email_verification_token_user
        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
);

CREATE INDEX idx_email_verification_token
    ON email_verification_tokens(token);
