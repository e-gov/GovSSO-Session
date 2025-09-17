package ee.ria.govsso.session.actuator.health;

import ee.ria.govsso.session.service.tara.TaraMetadataService;
import io.restassured.response.ValidatableResponse;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@RequiredArgsConstructor(onConstructor_ = @Autowired)
class ReadinessHealthEndpointTest extends HealthEndpointTest {

    private final TaraMetadataService taraMetadataService;

    @Test
    void healthReadiness_WhenAllIncludedServicesUp_RespondsWith200() {
        taraMetadataService.updateMetadata();
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
        taraMetadataService.updateMetadata();
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
