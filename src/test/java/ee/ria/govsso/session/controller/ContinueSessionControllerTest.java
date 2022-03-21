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
import static ee.ria.govsso.session.controller.ContinueSessionController.AUTH_VIEW_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static java.util.Collections.emptyMap;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.HttpHeaders.ORIGIN;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class ContinueSessionControllerTest extends BaseTest {

    private static final String TEST_LOGIN_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";

    @Test
    void continueSession_WhenFetchLoginRequestInfoIsSuccessful_CreatesSessionAndRedirects() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("/auth/login/test"));
    }

    @Test
    void continueSession_WhenCsrfTokenFormParameterMissing_ThrowsUserInputError() {
        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(403)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void continueSession_WhenCsrfTokenCookieMissing_ThrowsUserInputError() {
        given()
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(403)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void continueSession_WhenLoginChallengeFormParamIsMissing_ThrowsUserInputError() {
        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: continueSession.loginChallenge: Incorrect login_challenge format");
    }

    @Test
    void continueSession_WhenLoginChallengeIncorrectFormat_ThrowsUserInputError() {
        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("loginChallenge", "incorrect_format_login_challenge_#%")
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: continueSession.loginChallenge: Incorrect login_challenge format");
    }

    @Test
    void continueSession_WhenFetchLoginRequestInfoSubjectIsEmpty_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Login request subject must not be empty");
    }

    @Test
    void continueSession_WhenFetchLoginRequestInfoIdTokenHintClaimIsNonEmpty_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_id_token_hint_claim_non_empty_with_subject.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Login request ID token hint claim must be null");
    }

    @Test
    void continueSession_WhenOriginHeaderIsSet_NoCorsResponseHeadersAreSet() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .header(ORIGIN, "https://clienta.localhost:11443")
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .headers(emptyMap())
                .header("Location", Matchers.containsString("/auth/login/test"));
    }

    @Test
    void continueSession_WhenConsentsAreMissing_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_missing.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: No valid consent requests found");
    }
}
