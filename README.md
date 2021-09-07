<img src="src/main/resources/static/assets/eu_regional_development_fund_horizontal.jpg" width="350" height="200" alt="European Union European Regional Development Fund"/>

# GOVSSO Session Service

TODO What this application does.

## Prerequisites

* Java 17 JDK

## Building Dependencies

1. Follow TARA2-Admin/README.md to build it's Docker image 
2. ```shell
   docker compose build --build-arg genkeys=true
   ```

### Running GOVSSO Session Service Locally and Dependencies in Docker Compose

```shell
./mvnw spring-boot:run
docker compose up
```

## Running All in Docker Compose

```shell
./mvnw spring-boot:build-image
docker compose -f docker-compose.yml -f docker-compose-all.yml up
```

## Usage

* https://localhost:8451/ui/ - client UI.
* http://localhost:12080/ - admin UI (username admin, password admin).

## Configuration

TODO
