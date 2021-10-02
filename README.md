<img src="src/main/resources/static/assets/eu_regional_development_fund_horizontal.jpg" width="350" height="200" alt="European Union European Regional Development Fund"/>

# GOVSSO Session Service

TODO What this application does.

## Prerequisites

* Java 17 JDK

## Building Dependencies

1. Follow TARA2-Admin/README.md to build it's Docker image
2. ```shell
   docker compose build
   ```

## Running GOVSSO Session Service Locally and Dependencies in Docker Compose

```shell
./mvnw spring-boot:run
docker compose up
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
   docker compose -f docker-compose.yml -f docker-compose-all.yml up
   ```

## Endpoints

* Dozzle (log viewer)
    * http://localhost:9080/ - UI
* Example Client A
    * https://localhost:11443/ui/ - UI
* Hydra
    * http://localhost:13444/ - public API
        * http://localhost:13444/health/ready
        * http://localhost:13444/.well-known/openid-configuration
        * http://localhost:13444/.well-known/jwks.json
        * http://localhost:13444/oauth2/auth
        * http://localhost:13444/oauth2/token
    * http://localhost:13445/ - admin API
        * http://localhost:13445/health/alive
        * http://localhost:13445/version
        * https://www.ory.sh/hydra/docs/reference/api/#tag/admin
* Session Service
    * http://localhost:14080/actuator/health
    * http://localhost:14080/actuator/health/readiness
    * http://localhost:14080/actuator/info
* TARA Mock
    * https://localhost:15443/health
    * https://localhost:15443/oidc/.well-known/openid-configuration
    * https://localhost:15443/oidc/jwks
    * https://localhost:15443/oidc/authorize
    * https://localhost:15443/oidc/token
* Admin Service
    * http://localhost:16080/ - UI (username admin, password admin)
    * http://localhost:16080/actuator/health
* MailHog
    * http://localhost:17080/ - UI

## Configuration

TODO
