DELETE
FROM public.hydra_oauth2_authentication_session
;

DELETE
FROM public.hydra_oauth2_code
;

DELETE
FROM public.hydra_oauth2_oidc
;

DELETE
FROM public.hydra_oauth2_pkce
;

DELETE
FROM public.hydra_oauth2_flow
;

DELETE FROM public.hydra_oauth2_access;

DELETE FROM public.hydra_oauth2_refresh;
-- hydra_oauth2_jti_blacklist, hydra_oauth2_obfuscated_authentication_session, hydra_oauth2_trusted_jwt_bearer_issuer
-- are empty in our use cases

DELETE
FROM public.hydra_oauth2_logout_request
;

-- hydra_client, hydra_jwk, schema_migration must NOT be cleaned
