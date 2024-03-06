<img src="src/main/resources/static/assets/eu_regional_development_fund_horizontal.jpg" width="350" height="200" alt="European Union European Regional Development Fund"/>

# GovSSO Session Service

GovSSO Session is a webapp that integrates with the [Ory Hydra OIDC server](https://github.com/ory/hydra)
implementation. GovSSO Session provides [login](https://www.ory.sh/hydra/docs/concepts/login)
, [consent](https://www.ory.sh/hydra/docs/concepts/login) and [logout](https://www.ory.sh/docs/hydra/concepts/logout)
flow implementations.

## Prerequisites

* Java 17 JDK

## Building Dependencies

1. Follow [TARA-GovSSO-Admin/README.md](https://github.com/e-gov/TARA-GovSSO-Admin#building-and-running-in-docker) to
   build it's Docker image
2. Follow [TARA-GovSSO-ExampleClient/README.md](https://github.com/e-gov/TARA-GovSSO-ExampleClient#running-in-docker) to
   build it's Docker image
3. Build  [Ory Hydra HSM Docker image](https://github.com/ory/hydra/blob/v2.1.2/.docker/Dockerfile-hsm)
    ```shell
    docker build -f .docker/Dockerfile-hsm -t oryd/hydra:feature-govsso https://github.com/ory/hydra.git#v2.1.2
    ```
4. Generate required resources (TLS certificates, TARA id-token keys, etc.)
   ```shell
   cd ./local
   ./generate-resources.sh
   ```
5. ```shell
   docker compose build
   ```

## Running GovSSO Session Service Locally and Dependencies in Docker Compose

1. Add `127.0.0.1 tara.localhost` line to `hosts` file. This is needed only for requests originating from GovSSO-Session
   when it's running locally (not in Docker Compose) or during tests. It's not needed for web browsers as popular
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
                 --add-host=hydra.localhost:127.0.0.1 \
                 --add-host=tara.localhost:127.0.0.1 \
                 --add-host=admin.localhost:127.0.0.1 \
                 maven:3.9-eclipse-temurin-17 \
                 mvn spring-boot:build-image
      ```
      Git Bash users on Windows should add `MSYS_NO_PATHCONV=1` in front of the command.
2. Run
   ```shell
   docker compose up
   ```

## Clean Ory Hydra database

1. Run Ory Hydra janitor container which runs Ory Hydra janitor and a custom clean-up script
   ```shell
   docker-compose --profile hydra-janitor up -d
   ```

## Running With Elastic APM enabled

1. Run
    ```shell
   docker compose -f docker-compose.yml -f docker-compose-elk.yml up
   ```
2. Open Kibana and explore APM module for metrics and application logs.

## Endpoints

* Dozzle (log viewer)
    * http://localhost:9080/ - UI
* Example Client A
    * https://clienta.localhost:11443/ - UI
    * https://clienta.localhost:11443/actuator - maintenance endpoints
* Example Client B
    * https://clientb.localhost:12443/ - UI
    * https://clientb.localhost:12443/actuator - maintenance endpoints
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
    * https://session.localhost:15443/actuator - maintenance endpoints
* TARA Mock
    * https://tara.localhost:16443/health
    * https://tara.localhost:16443/.well-known/openid-configuration
    * https://tara.localhost:16443/oidc/jwks
    * https://tara.localhost:16443/oidc/authorize
    * https://tara.localhost:16443/oidc/token
* Admin Service
    * https://admin.localhost:17443/ - UI (username admin, password admin)
    * https://admin.localhost:17443/actuator - maintenance endpoints
* MailHog
    * http://localhost:18080/ - UI
* Kibana
    * http://localhost:23601/ - UI

## Configuration

<a name="sso_session_service_conf"></a>

### SSO Session service configuration

| Parameter        | Mandatory | Default value | Description, example |
| :---------------- | :---------- | :---------- | :---------------- |
| `govsso.base-url` | Yes | | Base URL of the SSO incoming proxy, for example: https://inproxy.localhost:13443/ |
| `govsso.session-max-update-interval-minutes` | Yes | | Sets how long the authentication should be remembered for in SSO OIDC service. NB! Must be the same as `ttl/id_token` value in Ory Hydra configuration. NB! Ory Hydra database clean-up functionality will remove session data older than 24 hours, so setting this value over 1440 (24 hours) also requires increasing Hydra database clean-up time limit. |
| `govsso.session-max-duration-hours` | Yes | | Sets how long the id token will be considered valid. NB! Ory Hydra database clean-up functionality will remove session data older than 24 hours, so setting this value over 24 also requires increasing Hydra database clean-up time limit. |

<a name="hydra_integration_conf"></a>

### Integration with Ory Hydra service

| Parameter        | Mandatory | Default value | Description, example |
| :---------------- | :---------- | :---------- | :---------------- |
| `govsso.hydra.admin-url` | Yes | | Point to Ory Hydra Administrative API |

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
| `govsso.tara.connect-timeout-milliseconds` | No | 5000 | Maximum period in milliseconds to establish a connection to TARA OIDC endpoints. |
| `govsso.tara.read-timeout-milliseconds` | No | 5000 | Maximum period in milliseconds to wait for response from TARA OIDC endpoints. |
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

<a name="admin_integration_conf"></a>

### Integration with Admin service

| Parameter        | Mandatory | Default value | Description, example |
| :---------------- | :---------- | :---------- | :---------------- |
| `govsso.admin.host-url` | Yes | | Point to Admin service host url |

<a name="admin_tls_conf"></a>

### TLS configuration for outbound connections

| Parameter        | Mandatory | Default value | Description, example |
| :---------------- | :---------- | :---------- | :---------------- |
| `govsso.admin.tls.trust-store-location` | Yes | | Location of the truststore containing trusted CA certificates. |
| `govsso.admin.tls.trust-store-password` | Yes | | Truststore password |
| `govsso.admin.tls.trust-store-type` | No | PKCS12 | Truststore type (jks, pkcs12). |

<a name="alerts_conf"></a>

## Alerts configuration

| Parameter        | Mandatory | Default value | Description, example |
| :---------------- | :---------- | :---------- | :---------------- |
| `govsso.alerts.enabled` | No | false | Enables alerts update service.|
| `govsso.alerts.refresh-alerts-interval-in-milliseconds` | No | 10000 | How often alerts are requested from the configured alerts url. Minimum value 1000. |
| `govsso.alerts.static-alert.message-templates[x].message` | No | | Static alert message, may contain HTML (non-HTML content must be HTML-escaped). |
| `govsso.alerts.static-alert.message-templates[x].locale` | No | | Static alert message locale. Example value: `et` |

Where x denotes index. Example:

````
govsso.alerts.static-alert.message-templates[0].message=Tegemist on testkeskkonnaga ja autentimiseks vajalik info on <a href="https://e-gov.github.io/GOVSSO/Testing">GovSSO dokumentatsioonis</a>!
govsso.alerts.static-alert.message-templates[0].locale=et
govsso.alerts.static-alert.message-templates[1].message=This is a test environment and necessary information for testing is available in <a href="https://e-gov.github.io/GOVSSO/Testing">GovSSO documentation</a>!
govsso.alerts.static-alert.message-templates[1].locale=en
govsso.alerts.static-alert.message-templates[2].message=Это тестовая среда, и информация, необходимая для аутентификации, находится в <a href="https://e-gov.github.io/GOVSSO/Testing">документации GovSSO</a>!
govsso.alerts.static-alert.message-templates[2].locale=ru
````

## Non-pom.xml Licenses

* [jquery](https://jquery.com) - MIT license
* [Roboto font](https://fonts.google.com/specimen/Roboto) - Apache 2.0 license
* [Maven Wrapper](https://maven.apache.org/wrapper/) - Apache 2.0 license
