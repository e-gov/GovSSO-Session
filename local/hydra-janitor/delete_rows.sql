-- Hydra janitor command is no longer used because it applies global TTLs and cannot
-- differentiate retention periods by client type.

-- Delete flows with variable retention based on client type.
-- DEFAULT clients: 1 day, SECURED_APP clients: 90 days.
-- Cascades to: hydra_oauth2_access, hydra_oauth2_code, hydra_oauth2_oidc,
-- hydra_oauth2_pkce, hydra_oauth2_refresh (all have challenge_id FK to
-- hydra_oauth2_flow.consent_challenge_id with ON DELETE CASCADE).
-- No separate DELETE statements are needed for those 5 tables because GovSSO
-- uses only the authorization code flow, where challenge_id is always populated.
DELETE
FROM public.hydra_oauth2_flow f
USING public.hydra_client c
WHERE f.client_id = c.id AND f.nid = c.nid
  AND f.requested_at < NOW() AT TIME ZONE 'UTC' - CASE
      WHEN c.metadata::jsonb ->> 'client_type' = 'SECURED_APP'
      THEN INTERVAL '90 DAYS'
      ELSE INTERVAL '1 DAY'
  END;

-- Delete authentication sessions that are no longer needed.
-- Flows must be deleted first to avoid unnecessary ON DELETE SET NULL updates
-- on hydra_oauth2_flow.login_session_id when sessions are removed.
-- NOT EXISTS ensures SECURED_APP sessions are preserved while their flows
-- (up to 90 days) still reference them.
DELETE
FROM public.hydra_oauth2_authentication_session s
WHERE (s.authenticated_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY'
       AND NOT EXISTS (SELECT 1 FROM public.hydra_oauth2_flow f WHERE f.login_session_id = s.id))
   OR (s.authenticated_at IS NULL
       AND NOT EXISTS (SELECT 1 FROM public.hydra_oauth2_flow f
                       WHERE f.login_session_id = s.id
                       AND f.requested_at >= NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY'));

-- hydra_oauth2_jti_blacklist, hydra_oauth2_obfuscated_authentication_session, hydra_oauth2_refresh, hydra_oauth2_trusted_jwt_bearer_issuer
-- are empty in our use cases

DELETE
FROM public.hydra_oauth2_logout_request lr
WHERE NOT EXISTS (
    SELECT 1 FROM public.hydra_oauth2_authentication_session s
    WHERE s.id = lr.sid
);

-- hydra_client, hydra_jwk, schema_migration must NOT be cleaned
