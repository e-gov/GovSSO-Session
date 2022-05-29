package ee.ria.govsso.session.actuator.health;

import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

class ApplicationHealthEndpointTest extends HealthEndpointTest {

    @Test
    void health_WhenAllServicesUp_RespondsWith200() {
        mockHydraHealthAliveUp();

        ValidatableResponse response = given()
                .when()
                .get("/actuator/health")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"))
                .body("components.diskSpace.status", equalTo("UP"))
                .body("components.hydra.status", equalTo("UP"))
                .body("components.tara.status", equalTo("UP"))
                .body("components.livenessState.status", equalTo("UP"))
                .body("components.ping.status", equalTo("UP"))
                .body("components.readinessState.status", equalTo("UP"))
                .body("groups", equalTo(List.of("liveness", "readiness")));

        assertTrustStoreHealthUp(response, "components.truststore.");
    }

    // "/actuator/health/readiness" endpoint outcome depends on other services (including Hydra status),
    // but readiness in general health endpoint does not.
    @Test
    void health_WhenAllServicesButHydraUp_RespondsWith503ButReadinessUp() {
        mockHydraHealthAliveDown();

        given()
                .when()
                .get("/actuator/health")
                .then()
                .assertThat()
                .statusCode(503)
                .body("status", equalTo("DOWN"))
                .body("components.hydra.status", equalTo("DOWN"))
                .body("components.readinessState.status", equalTo("UP"));
    }

    @Test
    void healthHydra_WhenHydraHealthEndpointRespondsWith200_RespondsWith200AndHydraStatusUp() {
        mockHydraHealthAliveUp();

        given()
                .when()
                .get("/actuator/health/hydra")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    void healthHydra_WhenHydraHealthEndpointRespondsWithError_RespondsWith503AndHydraStatusDown() {
        mockHydraHealthAliveDown();

        given()
                .when()
                .get("/actuator/health/hydra")
                .then()
                .assertThat()
                .statusCode(503)
                .body("status", equalTo("DOWN"));
    }

    @Test
    void healthTrustStore_WhenAllTrustStoreStatusesHealthUp_RespondsWith200AndTrustStoreStatusUp() {
        ValidatableResponse response = given()
                .when()
                .get("/actuator/health/truststore")
                .then()
                .assertThat()
                .statusCode(200);

        assertTrustStoreHealthUp(response, "");
    }

    @Test
    void healthTara_WhenTaraRespondsWithMetadata_RespondsWith200AndTaraStatusUp() {
        given()
                .when()
                .get("/actuator/health/tara")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }
}
