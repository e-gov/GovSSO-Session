package ee.ria.govsso.session.health;

import ee.ria.govsso.session.BaseTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;

public class ApplicationHealthEndpointTest extends BaseTest {

    @Test
    void applicationHealth_ok() {

        given()
                .when()
                .get("/actuator/health/readiness")
                .then()
                .assertThat()
                .statusCode(200);
    }

}
