<img src="src/main/resources/static/assets/eu_regional_development_fund_horizontal.jpg" width="350" height="200" alt="European Union European Regional Development Fund"/>

# GOVSSO Session Service

TODO What this application does.

## Prerequisites

* Java 17 JDK

## Building Dependencies

1. Follow [TARA2-Admin/README.md](https://github.com/e-gov/TARA2-Admin#building-and-running-in-docker) to build it's Docker image
2. Follow [GOVSSO-Client/README.md](https://github.com/e-gov/GOVSSO-Client#running-in-docker) to build it's Docker image
3. Build  [Ory Hydra HSM Docker image](https://github.com/ory/hydra/blob/v1.11.7/.docker/Dockerfile-hsm)
    ```shell
    docker build -f .docker/Dockerfile-hsm -t oryd/hydra:feature-govsso https://github.com/ory/hydra.git#v1.11.7
    ```
4. Generate TLS certificates. Stored locally in local/tls folder.
   ```shell
   cd local/tls
   ./generate-certificates.sh
   ```
5. ```shell
   docker compose build
   ```

## Running GOVSSO Session Service Locally and Dependencies in Docker Compose

1. Add `127.0.0.1 tara.localhost` line to `hosts` file. This is needed only for requests originating from
   session-service when it's running locally (not in Docker Compose). It's not needed for web browsers as popular
   browsers already have built-in support for resolving `*.localhost` subdomains.
   **NB! Also add given lines to docker-compose.yml gateway configuration with your local ip address.**
   ```shell
   extra_hosts:
     - "session:<your-local-ip-address>"
   ```
2. ```shell
   docker compose up
   docker compose stop session
   ./mvnw spring-boot:run
   ```

## Running All in Docker Compose

1. Build
    * Either build locally
      ```shell
      ./mvnw spring-boot:build-image
      ```
    * Or build in Docker
      ```shell
      docker run --pull always --rm \
                 -v /var/run/docker.sock:/var/run/docker.sock \
                 -v "$HOME/.m2:/root/.m2" \
                 -v "$PWD:/usr/src/project" \
                 -w /usr/src/project \
                 maven:3.8.2-openjdk-17 \
                 mvn spring-boot:build-image
      ```
      Git Bash users on Windows should add `MSYS_NO_PATHCONV=1` in front of the command.
2. Run
   ```shell
   docker compose up
   ```

## Endpoints

* Dozzle (log viewer)
    * http://localhost:9080/ - UI
* Example Client A
    * https://clienta.localhost:11443/ - UI
* Example Client B
    * https://clientb.localhost:12443/ - UI
* Ory Hydra
    * https://hydra.localhost:14443/ - public API
        * https://hydra.localhost:14443/health/ready
        * https://hydra.localhost:14443/.well-known/openid-configuration
        * https://hydra.localhost:14443/.well-known/jwks.json
        * https://hydra.localhost:14443/oauth2/auth
        * https://hydra.localhost:14443/oauth2/token
    * https://hydra.localhost:14445/ - admin API
        * https://hydra.localhost:14445/health/alive
        * https://hydra.localhost:14445/version
        * https://www.ory.sh/hydra/docs/reference/api/#tag/admin
* Session Service
    * https://session.localhost:15443/actuator/health
    * https://session.localhost:15443/actuator/health/readiness
    * https://session.localhost:15443/actuator/info
* TARA Mock
    * https://tara.localhost:16443/health
    * https://tara.localhost:16443/.well-known/openid-configuration
    * https://tara.localhost:16443/oidc/jwks
    * https://tara.localhost:16443/oidc/authorize
    * https://tara.localhost:16443/oidc/token
* Admin Service
    * https://admin.localhost:17443/ - UI (username admin, password admin)
    * https://admin.localhost:17443/actuator/health
* MailHog
    * http://localhost:18080/ - UI

## Configuration

TODO

<a name="sso_session_service_conf"></a>

### SSO Session service configuration

| Parameter        | Mandatory | Default value | Description, example |
| :---------------- | :---------- | :---------- | :---------------- |
| `govsso.base-url` | Yes | | Base URL of the SSO gateway service, for example: https://gateway.localhost:13443/ |
| `govsso.session-max-update-interval-minutes` | Yes | | sets how long the authentication should be remembered for in SSO OIDC service. |
| `govsso.session-max-duration-hours` | Yes | | Sets how long the id token will be considered valid. |

<a name="hydra_integration_conf"></a>

### Integration with Hydra OIDC service

| Parameter        | Mandatory | Default value | Description, example |
| :---------------- | :---------- | :---------- | :---------------- |
| `govsso.hydra.admin-url` | Yes | | Point to ORY Hydra Administrative API |

<a name="hydra_tls_conf"></a>

### TLS configuration for outbound connections

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `govsso.hydra.tls.trust-store-location` | Yes | Location of the truststore containing trusted CA certificates. |
| `govsso.hydra.tls.trust-store-password` | Yes | Truststore password |
| `govsso.hydra.tls.trust-store-type` | No | Truststore type (jks, pkcs12). Defaults to PKCS12 if not specified |

<a name="tara_integration_conf"></a>

### Integration with TARA OIDC service

| Parameter        | Mandatory | Default value | Description, example |
| :---------------- | :---------- | :---------- | :---------------- |
| `govsso.tara.issuer-url` | Yes | | TARA OIDC issuer URL where URI `${govsso.tara.issuer-url}/.well-known/openid-configuration` returns OIDC well known configuration. Issuer URL must **exactly** match issuer value published in OIDC configuration. |
| `govsso.tara.client-id` | Yes | | TARA client identifier. The client ID is issued by [RIA](https://www.ria.ee/). |
| `govsso.tara.client-secret` | Yes | | TARA client password. The client password is issued by [RIA](https://www.ria.ee/). |
| `govsso.tara.max-clock-skew-seconds` | No | 10 | Maximum allowed clock skew in seconds, when validating identity token. |
| `govsso.tara.metadata-interval` | No | PT24H | TARA OIDC well known configuration update interval. The time unit is milliseconds or in [ISO-8601 duration format](https://docs.oracle.com/javase/8/docs/api/java/time/Duration.html#parse-java.lang.CharSequence-). |
| `govsso.tara.metadata-max-attempts` | No | 1440 | Maximum attempts to retry metadata request on error. |
| `govsso.tara.metadata-backoff-delay-milliseconds` | No | 1000 | Initial delay time in milliseconds between retries. |
| `govsso.tara.metadata-backoff-max-delay-milliseconds` | No | 60000 | Maximum delay time in milliseconds between retries after applying backoff multiplier to initial delay time. |
| `govsso.tara.metadata-backoff-multiplier` | No | 1.1 | Multiplier for generating the next delay for backoff. |

<a name="tara_tls_conf"></a>

### TLS configuration for outbound connections

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.tls.trust-store-location` | Yes | Location of the truststore containing trusted CA certificates. |
| `tara.tls.trust-store-password` | Yes | Truststore password |
| `tara.tls.trust-store-type` | No | Truststore type (jks, pkcs12). Defaults to PKCS12 if not specified |
| `tara.tls.default-protocol` | No | Default protocol (see the list of supported [values](https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#sslcontext-algorithms)). Defaults to `TLS` if not specified |

<a name="sec_conf"></a>

## Security configuration

| Parameter        | Mandatory | Default value | Description, example |
| :---------------- | :---------- | :---------- | :---------------- |
| `govsso.security.content-security-policy` | No | | Content security policy. Default value `connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content` |
| `govsso.security.cookie-signing-secret` | Yes | | Login flow cookie signing secret. Minimum length 32. |
| `govsso.security.cookie-max-age-seconds` | No | 3600 | Login flow cookie max age in seconds. Minimum value -1. A positive value indicates when the cookie should expire relative to the current time. A value of 0 means the cookie should expire immediately. A negative value results in no "Max-Age" attribute in which case the cookie is removed when the browser is closed. |
| `govsso.security.masked-field-names` | No | Comma separated field names to mask when structurally logging objects. |

## Licenses

* [jquery](https://jquery.com) - MIT license
* [Roboto font](https://fonts.google.com/specimen/Roboto) - Apache 2.0 license
