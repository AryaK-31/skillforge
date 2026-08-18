DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM email_verification_tokens
        WHERE length(token) > 100
    ) THEN
        RAISE EXCEPTION 'Cannot shrink email_verification_tokens.token to VARCHAR(100): existing token exceeds 100 characters';
    END IF;
END $$;

ALTER TABLE email_verification_tokens
    ALTER COLUMN token TYPE VARCHAR(100);

ALTER TABLE email_verification_tokens
    DROP COLUMN created_at,
    DROP COLUMN updated_at;

ALTER TABLE email_verification_tokens
    RENAME CONSTRAINT fk_email_verification_token_user
        TO fk_email_verification_user;
