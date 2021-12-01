package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.session.SsoSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class AuthInitControllerTest extends BaseTest {

    private static final String TEST_LOGIN_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";

    private final SessionRepository<? extends Session> sessionRepository;

    @Test
    void authInit_WhenFetchLoginRequestInfoIsSuccessful_Redirects() {

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        String cookie = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.matchesRegex("https:\\/\\/localhost:9877\\/oidc\\/authorize\\?scope=openid&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A9877%2Fauth%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .extract().cookie("SESSION");

        SsoSession ssoSession = sessionRepository.findById(decodeCookieFromBase64(cookie)).getAttribute(SSO_SESSION);
        assertThat(ssoSession.getLoginRequestInfo().getChallenge(), equalTo(TEST_LOGIN_CHALLENGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "......", "123456789012345678901234567890123456789012345678900"})
    void authInit_WhenLoginChallengeInvalid_ThrowsUserInputError(String loginChallenge) {
        given()
                .param("login_challenge", loginChallenge)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authInit_WhenLoginChallengeMissing_ThrowsUserInputError() {
        given()
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authInit_WhenFetchLoginRequestInfoRespondsWith404_ThrowsUserInputError() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authInit_WhenFetchLoginRequestInfoRespondsWith410_ThrowsUserInputError() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(410)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authInit_WhenFetchLoginRequestInfoRespondsWith500_ThrowsSsoException() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_sso_oidc_login_request.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

}
