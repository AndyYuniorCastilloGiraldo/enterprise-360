CREATE TABLE auth_session (
    id UUID PRIMARY KEY,
    usuario_id UUID NOT NULL REFERENCES usuario(id),
    empresa_id UUID NOT NULL REFERENCES empresa(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT ck_auth_session_expiry CHECK (expires_at > created_at)
);

CREATE INDEX idx_auth_session_user_tenant_active
    ON auth_session(usuario_id, empresa_id, revoked_at);

CREATE TABLE refresh_token (
    id UUID PRIMARY KEY,
    auth_session_id UUID NOT NULL REFERENCES auth_session(id),
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by_id UUID REFERENCES refresh_token(id),
    CONSTRAINT ck_refresh_token_expiry CHECK (expires_at > created_at)
);

CREATE INDEX idx_refresh_token_session
    ON refresh_token(auth_session_id);
