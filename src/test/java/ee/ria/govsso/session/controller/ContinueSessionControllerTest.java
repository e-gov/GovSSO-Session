package ee.ria.govsso.session.controller;

import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.govsso.session.BaseTest;
import io.restassured.http.Cookie;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.stream.Stream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.putRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.configuration.SecurityConfiguration.COOKIE_NAME_XSRF_TOKEN;
import static ee.ria.govsso.session.controller.ContinueSessionController.AUTH_VIEW_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static java.util.Collections.emptyMap;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.springframework.http.HttpHeaders.ORIGIN;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class ContinueSessionControllerTest extends BaseTest {
    private final Cookie MOCK_OIDC_SESSION_COOKIE = new Cookie.Builder("__Host-ory_hydra_session", "MDAwMDAwMDAwMHxaR0YwWVRFeU16UTFOamM0T1RBZ1pUVTJZMkpoWmprdE9ERmxPUzAwTkRjekxXRTNNek10TWpZeFpUaGtaRE00WlRrMUlHUmhkR0V4TWpNME5UWTNPRGt3fGludmFsaWRfaGFzaA==").build();

    static Stream<Arguments> contextHeaders() {
        return Stream.of(
                arguments("X-Forwarded-For", "111.111.111.111", "$.context.ip_address"),
                arguments("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36", "$.context.user_agent")
        );
    }

    @Test
    void continueSession_WhenFetchLoginRequestInfoIsSuccessful_CreatesSessionAndRedirects() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
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
                .formParam("_csrf", XORED_CSRF_TOKEN)
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
                .formParam("_csrf", XORED_CSRF_TOKEN)
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
                .formParam("_csrf", XORED_CSRF_TOKEN)
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
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
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
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_id_token_hint_claim_non_empty_with_subject.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
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
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
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

    @ParameterizedTest
    @MethodSource("contextHeaders")
    void continueSession_WhenHeaderIsSet_ContextContainsHeaderValue(String headerName, String expectedContextValue, String expectedContextJsonPath) {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .header(headerName, expectedContextValue)
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("/auth/login/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/admin/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .withRequestBody(matchingJsonPath(expectedContextJsonPath, WireMock.equalTo(expectedContextValue))));
    }

    @Test
    void continueSession_WhenConsentsAreMissing_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_missing.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
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

    @ParameterizedTest
    @ValueSource(strings = {
            "mock_sso_oidc_login_request_with_requested_at_below_lower_bound.json",
            "mock_sso_oidc_login_request_with_requested_at_above_upper_bound.json"})
    void continueSession_WhenNoConsentsFoundAtLoginRequestTime_ThrowsTechnicalGeneralError(String loginRequest) {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/" + loginRequest)));
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
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

    @Test
    void continueSession_WhenLoginResponseRequestUrlDoesntContainPromptConsent_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_url_with_subject_without_prompt_consent.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Request URL must contain prompt value");
    }

    @Test
    void continueSession_WhenLoginResponseRequestUrlContainsInvalidPromptValue_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_invalid_prompt_value.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Invalid prompt value");
    }

    @Test
    void continueSession_WhenConsentsIdTokenAcrValueLowerThanLoginRequestInfoAcrValue_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_first_acr_value_low.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: ID Token acr value must be equal to or higher than hydra login request acr");
    }

    @Test
    void continueSession_WhenLoginResponseRequestWithInvalidScope_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_with_idcard.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Requested scope must contain openid and may contain phone, representee.* and representee_list, but nothing else");
    }

    @Test
    void continueSession_WhenLoginResponseRequestScopeWithOpenidAndInvalidScope_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_with_openid_and_idcard.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Requested scope must contain openid and may contain phone, representee.* and representee_list, but nothing else");
    }

    @Test
    void continueSession_WhenLoginResponseRequestScopeContainsOnlyPhone_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_with_phone.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Requested scope must contain openid and may contain phone, representee.* and representee_list, but nothing else");
    }

    @Test
    void continueSession_WhenLoginResponseRequestHasMoreThanOneAcrValue_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_more_than_one_acr.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: acrValues must contain only 1 value");
    }

    @Test
    void continueSession_WhenLoginResponseRequestHasOneIncorrectAcrValue_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_one_incorrect_acr.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: acrValues must be one of low/substantial/high");
    }

    @Test
    void continueSession_WhenLoginResponseRequestHasOneCapitalizedAcrValue_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_capitalized_acr.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: acrValues must be one of low/substantial/high");
    }

    @Test
    void loginInit_WhenSessionContinuationWithoutOidcSessionCookie_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Unable to continue session! Oidc session cookie not found.");
    }

    @Test
    void loginInit_WhenSessionContinuationWithoutOidcSessionCookieValue_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie("__Host-ory_hydra_session", "")
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Unable to continue session! Oidc session cookie not found.");
    }
}
