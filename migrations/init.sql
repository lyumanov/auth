CREATE TABLE IF NOT EXISTS users_tokens (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    token_id UUID NOT NULL,
    token_hash TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    CONSTRAINT unique_user_id UNIQUE(user_id, token_hash)
    );