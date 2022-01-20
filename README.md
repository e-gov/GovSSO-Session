<img src="src/main/resources/static/assets/eu_regional_development_fund_horizontal.jpg" width="350" height="200" alt="European Union European Regional Development Fund"/>

# GOVSSO Session Service

TODO What this application does.

## Prerequisites

* Java 17 JDK

## Building Dependencies

1. Follow TARA2-Admin/README.md to build it's Docker image
2. Follow GOVSSO-Client/README.md to build it's Docker image
3. ```shell
   docker compose build
   ```

## Running GOVSSO Session Service Locally and Dependencies in Docker Compose

1. Add `127.0.0.1 tara.localhost` line to `hosts` file. This is needed only for requests originating from
   session-service when it's running locally (not in Docker Compose). It's not needed for web browsers as popular
   browsers already have built-in support for resolving `*.localhost` subdomains.
   NB! Also have to change 'session' proxy_pass hosts to 'host.docker.internal' in local/gateway/nginx.conf.
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
    * https://localhost:11443/ - UI
* Example Client B
    * https://localhost:12443/ - UI
* Ory Hydra
    * http://localhost:14444/ - public API
        * http://localhost:14444/health/ready
        * http://localhost:14444/.well-known/openid-configuration
        * http://localhost:14444/.well-known/jwks.json
        * http://localhost:14444/oauth2/auth
        * http://localhost:14444/oauth2/token
    * http://localhost:14445/ - admin API
        * http://localhost:14445/health/alive
        * http://localhost:14445/version
        * https://www.ory.sh/hydra/docs/reference/api/#tag/admin
* Session Service
    * http://localhost:15080/actuator/health
    * http://localhost:15080/actuator/health/readiness
    * http://localhost:15080/actuator/info
* TARA Mock
    * https://tara.localhost:16443/health
    * https://tara.localhost:16443/.well-known/openid-configuration
    * https://tara.localhost:16443/oidc/jwks
    * https://tara.localhost:16443/oidc/authorize
    * https://tara.localhost:16443/oidc/token
* Admin Service
    * http://localhost:17080/ - UI (username admin, password admin)
    * http://localhost:17080/actuator/health
* MailHog
    * http://localhost:17080/ - UI

## Configuration

TODO

<a name="sso_session_service_conf"></a>

### SSO Session service configuration

| Parameter        | Mandatory | Default value | Description, example |
| :---------------- | :---------- | :---------- | :---------------- |
| `govsso.base-url` | Yes | | Base URL of the SSO Session service, for example: http://localhost:15080/ |
| `govsso.session-max-update-interval-minutes` | Yes | | sets how long the authentication should be remembered for in SSO OIDC service. |
| `govsso.session-max-duration-hours` | Yes | | Sets how long the id token will be considered valid. |

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

<a name="sec_conf"></a>

## Security configuration

| Parameter | Mandatory | Description, example |
|:--------- |:--------- |:-------------------- |
| `govsso.security.content-security-policy` | No | Content security policy. Default value `connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content` |

## Licenses

* [jquery](https://jquery.com) - MIT license
* [Roboto font](https://fonts.google.com/specimen/Roboto) - Apache 2.0 license
