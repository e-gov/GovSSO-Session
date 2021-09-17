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

## Usage

* https://localhost:8451/ui/ - client UI.
* http://localhost:12080/ - admin UI (username admin, password admin).

## Configuration

TODO
