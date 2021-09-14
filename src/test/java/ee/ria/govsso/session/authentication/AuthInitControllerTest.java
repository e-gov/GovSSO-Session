package ee.ria.govsso.session.authentication;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.session.SsoSession;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import java.util.Base64;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class AuthInitControllerTest extends BaseTest {

    private static final String TEST_LOGIN_CHALLENGE = "abcdefg098AAdsCC";

    @Autowired
    protected SessionRepository<Session> sessionRepository;

    @Test
    void authInit_Ok() {

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_response.json")));

        String cookie = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/url/test"))
                .extract().cookie("SESSION");

        log.info(cookie);

        SsoSession ssoSession = sessionRepository.findById(decodeCookieFromBase64(cookie)).getAttribute(SSO_SESSION);
        assertEquals(TEST_LOGIN_CHALLENGE, ssoSession.getLoginRequestInfo().getChallenge());
    }

    @Test
    void authInit_loginChallenge_EmptyValue() {
        given()
                .param("login_challenge", "")
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authInit.loginChallenge: only characters and numbers allowed"))
                .body("error", equalTo("Bad Request"));
    }

    @Test
    void authInit_loginChallenge_ParamMissing() {
        given()
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required request parameter 'login_challenge' for method parameter type String is not present"))
                .body("error", equalTo("Bad Request"));
    }

    @Test
    void authInit_loginChallenge_InvalidValue() {
        given()
                .param("login_challenge", "......")
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authInit.loginChallenge: only characters and numbers allowed"))
                .body("error", equalTo("Bad Request"));
    }

    @Test
    void authInit_loginChallenge_InvalidLength() {
        given()
                .param("login_challenge", "123456789012345678901234567890123456789012345678900")
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authInit.loginChallenge: size must be between 0 and 50"))
                .body("error", equalTo("Bad Request"));
    }

    @Test
    void authInit_OidcRespondsWith404() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_response.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("404 Not Found from GET https://localhost:9877/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE));
    }

    @Test
    void authInit_OidcRespondsWith500() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("500 Internal Server Error from GET https://localhost:9877/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE));
    }

    private String decodeCookieFromBase64(String cookie) {
        byte[] decodedBytes = Base64.getDecoder().decode(cookie);
        return new String(decodedBytes);
    }

}
