package ee.ria.govsso.session.actuator.health;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.paasuke.PaasukeGovssoClient;
import ee.ria.govsso.session.service.paasuke.PaasukeService;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static ee.ria.govsso.session.service.paasuke.PaasukeServiceTest.DELEGATE_ID;
import static ee.ria.govsso.session.service.paasuke.PaasukeServiceTest.REPRESENTEE_ID;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@RequiredArgsConstructor(onConstructor_ = @Autowired)
// DirtiesContext is required to make sure that the lastRequestToPaasukeSuccessful parameter in PaasukeService is in its
// original state when running this test class
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class PaasukeHealthIndicatorTest extends BaseTest {

    public static final PaasukeGovssoClient GOVSSO_CLIENT = new PaasukeGovssoClient("institution-id", "client-id");

    private final PaasukeService paasukeService;

    void mockRepresenteesRequestSuccessful() {
        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/delegates/Isikukood3/representees?ns=AGENCY-Q")
                .willReturn(aResponse().withStatus(200)));;
    }

    void mockRepresenteesRequestUnsuccessful() {
        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/delegates/Isikukood3/representees?ns=AGENCY-Q")
                .willReturn(aResponse().withStatus(400)));;
    }

    void mockMandatesRequestSuccessful() {
        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q")
                .willReturn(aResponse().withStatus(200)));;
    }

    void mockMandatesRequestUnsuccessful() {
        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q")
                .willReturn(aResponse().withStatus(400)));;
    }

    @Test
    @Order(1)
    void healthHydra_WhenPaasukeRequestHasNeverBeenMade_RespondsWith200AndPaasukeStatusUnknown() {

        given()
                .when()
                .get("/actuator/health/paasuke")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UNKNOWN"));
    }

    @Test
    @Order(2)
    void healthHydra_WhenRepresenteesRequestRespondsWith200_RespondsWith200AndPaasukeStatusUp() {
        mockRepresenteesRequestSuccessful();
        paasukeService.fetchRepresentees(DELEGATE_ID, "ns=AGENCY-Q", GOVSSO_CLIENT);

        given()
                .when()
                .get("/actuator/health/paasuke")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    @Order(3)
    void healthHydra_WhenMandatesRequestRespondsWith200_RespondsWith200AndPaasukeStatusUp() {
        mockMandatesRequestSuccessful();
        paasukeService.fetchMandates(REPRESENTEE_ID, DELEGATE_ID, "ns=AGENCY-Q", GOVSSO_CLIENT);

        given()
                .when()
                .get("/actuator/health/paasuke")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    @Order(4)
    void healthHydra_WhenRepresenteesRequestRespondsWith400_RespondsWith503AndPaasukeStatusDown() {
        mockRepresenteesRequestUnsuccessful();
        assertThrows(
                SsoException.class,
                () -> paasukeService.fetchRepresentees(DELEGATE_ID, "ns=AGENCY-Q", GOVSSO_CLIENT));

        given()
                .when()
                .get("/actuator/health/paasuke")
                .then()
                .assertThat()
                .statusCode(503)
                .body("status", equalTo("DOWN"));
    }

    @Test
    @Order(5)
    void healthHydra_WhenMandatesRequestRespondsWith400_RespondsWith503AndPaasukeStatusDown() {
        mockMandatesRequestUnsuccessful();
        assertThrows(
                SsoException.class,
                () -> paasukeService.fetchMandates(REPRESENTEE_ID, DELEGATE_ID, "ns=AGENCY-Q", GOVSSO_CLIENT));

        given()
                .when()
                .get("/actuator/health/paasuke")
                .then()
                .assertThat()
                .statusCode(503)
                .body("status", equalTo("DOWN"));
    }
}
