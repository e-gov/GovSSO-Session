package ee.ria.govsso.session.health;

import ee.ria.govsso.session.BaseTest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

public class ApplicationHealthEndpointTest extends BaseTest {

    @Test
    void health_WhenAllServicesUp_RespondsWith200() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/health/alive"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("{\"status\":\"ok\"}")));

        given()
                .when()
                .get("/actuator/health")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"))
                .body("components.diskSpace.status", equalTo("UP"))
                .body("components.hydra.status", equalTo("UP"))
                .body("components.livenessState.status", equalTo("UP"))
                .body("components.ping.status", equalTo("UP"))
                .body("components.readinessState.status", equalTo("UP"))
                .body("groups", equalTo(List.of("liveness", "readiness")));
        ;
    }

    @Test
    void healthReadiness_WhenAllServicesUp_RespondsWith200() {
        given()
                .when()
                .get("/actuator/health/readiness")
                .then()
                .assertThat()
                .statusCode(200);
    }

    @Test
    void healthHydra_WhenHydraHealthEndpointRespondsWith200_RespondsWith200AndHydraUp() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/health/alive"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("{\"status\":\"ok\"}")));

        given()
                .when()
                .get("/actuator/health/hydra")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    void healthHydra_WhenHydraHealthEndpointRespondsWithError_RespondsWith503AndHydraDown() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/health/alive"))
                .willReturn(aResponse()
                        .withStatus(400)));

        given()
                .when()
                .get("/actuator/health/hydra")
                .then()
                .assertThat()
                .statusCode(503)
                .body("status", equalTo("DOWN"));
    }

}
