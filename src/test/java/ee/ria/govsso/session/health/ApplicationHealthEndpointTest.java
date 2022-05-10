package ee.ria.govsso.session.health;

import ee.ria.govsso.session.BaseTest;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

class ApplicationHealthEndpointTest extends BaseTest {

    @Test
    void health_WhenAllServicesUp_RespondsWith200() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/health/alive"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("{\"status\":\"ok\"}")));

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
    void healthHydra_WhenHydraHealthEndpointRespondsWith200_RespondsWith200AndHydraStatusUp() {
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
    void healthHydra_WhenHydraHealthEndpointRespondsWithError_RespondsWith503AndHydraStatusDown() {
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

    private void assertTrustStoreHealthUp(ValidatableResponse response, String prefix) {
        response.body("status", equalTo("UP"))
                .body(prefix + "components.Hydra.status", equalTo("UP"))
                .body(prefix + "components.Hydra.details.certificates[0]", notNullValue())
                .body(prefix + "components.Hydra.details.certificates[0].alias", equalTo("govsso-ca.localhost"))
                .body(prefix + "components.Hydra.details.certificates[0].subjectDN", equalTo("CN=govsso-ca.localhost,O=govsso-local,L=Tallinn,C=EE"))
                .body(prefix + "components.Hydra.details.certificates[0].serialNumber", notNullValue())
                .body(prefix + "components.Hydra.details.certificates[0].state", equalTo("ACTIVE"))
                .body(prefix + "components.Hydra.details.certificates[1].", nullValue())
                .body(prefix + "components.TARA.status", equalTo("UP"))
                .body(prefix + "components.TARA.details.certificates[0]", notNullValue())
                .body(prefix + "components.TARA.details.certificates[0].alias", equalTo("tara-ca.localhost"))
                .body(prefix + "components.TARA.details.certificates[0].subjectDN", equalTo("CN=tara-ca.localhost,O=tara-local,L=Tallinn,C=EE"))
                .body(prefix + "components.TARA.details.certificates[0].serialNumber", notNullValue())
                .body(prefix + "components.TARA.details.certificates[0].state", equalTo("ACTIVE"))
                .body(prefix + "components.TARA.details.certificates[1].", nullValue());
    }

}
