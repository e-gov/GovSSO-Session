TRUNCATE public.hydra_oauth2_authentication_session, public.hydra_oauth2_code, public.hydra_oauth2_oidc, public.hydra_oauth2_pkce, public.hydra_oauth2_flow, public.hydra_oauth2_access, public.hydra_oauth2_refresh, public.hydra_oauth2_logout_request;

-- hydra_oauth2_jti_blacklist, hydra_oauth2_obfuscated_authentication_session, hydra_oauth2_trusted_jwt_bearer_issuer
-- are empty in our use cases

-- hydra_client, hydra_jwk, schema_migration must NOT be cleaned
