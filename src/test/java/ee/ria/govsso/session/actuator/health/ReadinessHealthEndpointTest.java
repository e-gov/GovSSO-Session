package ee.ria.govsso.session.actuator.health;

import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

class ReadinessHealthEndpointTest extends HealthEndpointTest {

    @Test
    void healthReadiness_WhenAllIncludedServicesUp_RespondsWith200() {
        mockHydraHealthAliveUp();

        ValidatableResponse response = given()
                .when()
                .get("/actuator/health/readiness")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"))
                .body("components.readinessState.status", equalTo("UP"))
                .body("components.hydra.status", equalTo("UP"))
                .body("components.tara.status", equalTo("UP"));

        assertTrustStoreHealthUp(response, "components.truststore.");
    }

    @Test
    void healthReadiness__WhenHydraServiceDownButOtherServicesUp_RespondsWith503AndHydraStatusDown() {
        mockHydraHealthAliveDown();

        ValidatableResponse response = given()
                .when()
                .get("/actuator/health/readiness")
                .then()
                .assertThat()
                .statusCode(503)
                .body("status", equalTo("DOWN"))
                .body("components.readinessState.status", equalTo("UP"))
                .body("components.hydra.status", equalTo("DOWN"))
                .body("components.tara.status", equalTo("UP"));

        assertTrustStoreHealthUp(response, "components.truststore.");
    }
}
