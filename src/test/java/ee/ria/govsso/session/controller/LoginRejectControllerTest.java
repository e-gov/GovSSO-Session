package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.configuration.SecurityConfiguration.COOKIE_NAME_XSRF_TOKEN;
import static ee.ria.govsso.session.controller.LoginRejectController.LOGIN_REJECT_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class LoginRejectControllerTest extends BaseTest {

    @Test
    void loginReject_WhenLoginRejectSuccessful_Redirects() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));
        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/login/reject?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_reject.json")));

        given()
                .when()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .post(LOGIN_REJECT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("/auth/reject/test"));
    }

    @Test
    void loginReject_WhenLoginChallengeFormParamIsMissing_ThrowsUserInputError() {

        given()
                .when()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .post(LOGIN_REJECT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: loginReject.loginChallenge: Incorrect login_challenge format");
    }

    @Test
    void loginReject_WhenLoginChallengeIncorrectFormat_ThrowsUserInputError() {
        given()
                .when()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("loginChallenge", "incorrect_format_login_challenge_#%")
                .post(LOGIN_REJECT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: loginReject.loginChallenge: Incorrect login_challenge format");
    }

    @Test
    void loginReject_WhenLoginRejectReturns404_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));
        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/login/reject?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)));

        given()
                .when()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .post(LOGIN_REJECT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to reject Hydra login request --> 404 Not Found from PUT");
    }

    @Test
    void loginReject_WhenLoginRejectReturns409_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));
        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/login/reject?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(409)));

        given()
                .when()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .post(LOGIN_REJECT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to reject Hydra login request --> 409 Conflict from PUT");
    }

    @Test
    void loginReject_WhenLoginRejectReturns500_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));
        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/login/reject?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .when()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .post(LOGIN_REJECT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: Failed to reject Hydra login request --> 500 Internal Server Error from PUT");
    }

    @Test
    void loginReject_WhenCsrfTokenFormParameterMissing_ThrowsUserInputError() {

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .when()
                .post(LOGIN_REJECT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(403)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginReject_WhenCsrfTokenCookieMissing_ThrowsUserInputError() {

        given()
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .when()
                .post(LOGIN_REJECT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(403)
                .body("error", equalTo("USER_INPUT"));
    }
}
