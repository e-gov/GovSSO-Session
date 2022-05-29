package ee.ria.govsso.session.actuator.health;

import ee.ria.govsso.session.BaseTest;
import io.restassured.response.ValidatableResponse;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

abstract class HealthEndpointTest extends BaseTest {

    void mockHydraHealthAliveUp() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/health/alive"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("{\"status\":\"ok\"}")));
    }

    void mockHydraHealthAliveDown() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/health/alive"))
                .willReturn(aResponse()
                        .withStatus(400)));
    }

    void assertTrustStoreHealthUp(ValidatableResponse response, String prefix) {
        response.body(prefix + "status", equalTo("UP"))
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
