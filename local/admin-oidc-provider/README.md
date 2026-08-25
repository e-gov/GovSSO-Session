# Admin OIDC provider

The local Admin OIDC provider uses NAV `mock-oauth2-server`. It supports OpenID Connect discovery, Authorization Code
Flow, JWKS, UserInfo and logout endpoints. It is used to test the Admin OIDC authentication flow locally.

Open the interactive login page through the Admin login flow and enter any non-empty subject. The configured callback
returns the example identity defined in the editable claims field. The mock's standard login template is overridden
only to prefill that field with example claims from `login.ftl`.
