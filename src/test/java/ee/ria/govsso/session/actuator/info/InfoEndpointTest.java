package ee.ria.govsso.session.actuator.info;

import ee.ria.govsso.session.BaseTest;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InfoEndpointTest extends BaseTest {

    @Test
    void info_currentTimeIsPresent() {
        String serveCurrentTimeStr = given()
                .when()
                .get("/actuator/info")
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .path("currentTime");

        assertNotNull(serveCurrentTimeStr);
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime serveCurrentTime = OffsetDateTime.parse(serveCurrentTimeStr);
        assertTrue(serveCurrentTime.isBefore(now));
        assertTrue(serveCurrentTime.isAfter(now.minus(Duration.ofMinutes(1))));
    }

    @Disabled("TODO GSSO-540")
    @Test
    void info_startTimeIsPresent() {
        String serviceStartTimeStr = given()
                .when()
                .get("/actuator/info")
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .path("startTime");

        assertNotNull(serviceStartTimeStr);
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime serveCurrentTime = OffsetDateTime.parse(serviceStartTimeStr);
        assertTrue(serveCurrentTime.isBefore(now));
        assertTrue(serveCurrentTime.isAfter(now.minus(Duration.ofMinutes(1))));
    }
}
