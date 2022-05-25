package ee.ria.govsso.session.service.tara;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.error.exceptions.SsoException;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

// To use package-protected method "updateMetadata", this test must be in this package thus cannot be in health package.
@Disabled // TODO: GSSO-444 Flaky during jenkins build only for unknown reason
@TestPropertySource(properties = {
        "govsso.tara.metadata-max-attempts=1",
})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class TaraHealthIndicatorTest extends BaseTest {

    private final TaraMetadataService taraMetadataService;

    @Test
    @Order(1)
    void health_WhenTaraRespondsWithMetadata_RespondsWith200AndTaraStatusUp() {
        // Default OK TARA metadata mocks are set in BaseTest

        given()
                .when()
                .get("/actuator/health/tara")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    @Order(2)
    void health_WhenGettingTaraMetadataFails_RespondsWith503AndTARAStatusDown() {
        // Override default TARA metadata mocks to return faulty response (any, in this context),
        // which sets metadata as null until next scheduled metadata update.
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_invalid_issuer.json");
        assertThrows(SsoException.class, taraMetadataService::updateMetadata);
        assertErrorIsLogged("Unable to update TARA metadata: Expected OIDC Issuer");

        given()
                .when()
                .get("/actuator/health/tara")
                .then()
                .assertThat()
                .statusCode(503)
                .body("status", equalTo("DOWN"));
    }

}
