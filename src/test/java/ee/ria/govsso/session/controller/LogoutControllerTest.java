package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.error.ErrorHandler;
import ee.ria.govsso.session.error.exceptions.SsoException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.SpyBean;

import java.io.IOException;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.configuration.SecurityConfiguration.COOKIE_NAME_XSRF_TOKEN;
import static ee.ria.govsso.session.controller.LogoutController.LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.LogoutController.LOGOUT_END_SESSION_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.LogoutController.LOGOUT_INIT_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesRegex;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class LogoutControllerTest extends BaseTest {
    public static final String TEST_LOGOUT_CHALLENGE = "3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931";

    @SpyBean
    private ErrorHandler errorHandler; // TODO GSSO-265 Must check but SpyBean creates new application context, so maybe create mock log appender instead for detailed exception message assertions.

    @Captor
    private ArgumentCaptor<Exception> exceptionCaptor;

    @Test
    void logoutInit_WhenValidSingleClientLogoutRequest_ReturnsRedirect() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_single_consent.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/accept?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", "https://clienta.localhost:11443");
    }

    @Test
    void logoutInit_WhenValidMultipleClientLogoutRequest_ReturnsLogoutView() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?client=client-a&subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a&all=false&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));


        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("You have been logged out of Teenusenimi A"))
                .body(matchesRegex("(?:.*\\r*\\n*)*You still have active sessions in the following applications:(?:.*\\r*\\n*){5}Teenusenimi B(?:.*\\r*\\n*){5}Do you want to log out of all applications(?:.*\\r*\\n*)*"));
    }

    @Test
    void logoutInit_WhenUnorderedDuplicateListOfConsents_ReturnsLogoutViewWithOrderedSessionNames() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_duplicate_unordered_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?client=client-a&subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a&all=false&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));


        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("You have been logged out of Teenusenimi A"))
                .body(matchesRegex("(?:.*\\r*\\n*)*You still have active sessions in the following applications:(?:.*\\r*\\n*){5}Teenusenimi B(?:.*\\r*\\n*){4}Teenusenimi C(?:.*\\r*\\n*){5}Do you want to log out of all applications(?:.*\\r*\\n*)*"));
        // For some reason <ul>[\n\r\s]*<li>[\n\r\s]*<strong>[\n\r\s]*Teenusenimi B[\n\r\s]*<\/strong>[\n\r\s]*<\/li>[\n\r\s]*<li>[\n\r\s]*<strong>[\n\r\s]*Teenusenimi C[\n\r\s]*<\/strong>[\n\r\s]*<\/li>[\n\r\s]*<\/ul> does not work
    }

    @Test
    void logoutInit_WhenNotRelyingPartyInitiatedLogoutRequest_ThrowsUserInputError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_rp_initiated_false.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("Logout not initiated by relying party"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "......", "00000000-1111-2222-3333-4444444444445", "00000000-1111-2222-3333444444444444", "3C3EF85A-3D8B-4EA2-BB53-B66BC5BD1931"})
    void logoutInit_WhenLogoutChallengeInvalid_ThrowsUserInputError(String logoutChallenge) throws IOException {

        given()
                .param("logout_challenge", logoutChallenge)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        verify(errorHandler).handleBindException(exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("logoutInit.logoutChallenge: must match \"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$\""));
    }

    @Test
    void logoutInit_WhenLogoutChallengeParamIsDuplicate_ThrowsUserInputError() {
        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .param("logout_challenge", "abcdeff098aadfccabcdeff098aadfca")
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void logoutInit_WhenLogoutChallengeMissing_ThrowsUserInputError() throws IOException {
        given()
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        verify(errorHandler).handleBindException(exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("Required request parameter 'logout_challenge' for method parameter type String is not present"));
    }

    @Test
    void logoutInit_WhenFetchLogoutRequestInfoRespondsWith404_ThrowsUserInputError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("404 Not Found from GET https://hydra.localhost:9000/oauth2/auth/requests/logout?logout_challenge=3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931"));
    }

    @Test
    void logoutInit_WhenFetchLogoutRequestInfoRespondsWith410_ThrowsUserInputError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(410)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("410 Gone from GET https://hydra.localhost:9000/oauth2/auth/requests/logout?logout_challenge=3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931"));
    }

    @Test
    void logoutInit_WhenFetchLogoutRequestInfoRespondsWith500_ThrowsTechnicalGeneralError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("500 Internal Server Error from GET https://hydra.localhost:9000/oauth2/auth/requests/logout?logout_challenge=3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931"));
    }

    @Test
    void logoutInit_WhenGetConsentsReturnsEmptyList_ThrowsTechnicalGeneralError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_missing.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(), equalTo("No valid consent requests found"));
    }

    @Test
    void logoutInit_WhenGetConsentsRespondsWith500_ThrowsTechnicalGeneralError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("500 Internal Server Error from GET https://hydra.localhost:9000/oauth2/auth/sessions/consent?subject=Isikukood3"));
    }

    @Test
    void logoutInit_WhenAcceptLogoutRespondsWith404_ThrowsUserInputError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_single_consent.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/accept?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("404 Not Found from PUT https://hydra.localhost:9000/oauth2/auth/requests/logout/accept?logout_challenge=3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931"));
    }

    @Test
    void logoutInit_WhenAcceptLogoutRespondsWith500_ThrowsTechnicalGeneralError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_single_consent.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/accept?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("500 Internal Server Error from PUT https://hydra.localhost:9000/oauth2/auth/requests/logout/accept?logout_challenge=3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931"));
    }

    @Test
    void endSession_WhenLogoutAccepted_ReturnsRedirect() {
        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/accept?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_END_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", "https://clienta.localhost:11443");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "......", "00000000-1111-2222-3333-4444444444445", "00000000-1111-2222-3333444444444444", "3C3EF85A-3D8B-4EA2-BB53-B66BC5BD1931"})
    void endSession_WhenLogoutChallengeInvalid_ThrowsUserInputError(String logoutChallenge) throws IOException {

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", logoutChallenge)
                .when()
                .post(LOGOUT_END_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        verify(errorHandler).handleBindException(exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("endSession.logoutChallenge: must match \"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$\""));
    }

    @Test
    void endSession_WhenAcceptLogoutRespondsWith404_ThrowsUserInputError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/accept?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_END_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("404 Not Found from PUT https://hydra.localhost:9000/oauth2/auth/requests/logout/accept?logout_challenge=3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931"));
    }

    @Test
    void endSession_WhenAcceptLogoutRespondsWith500_ThrowsTechnicalGeneralError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/accept?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_END_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("500 Internal Server Error from PUT https://hydra.localhost:9000/oauth2/auth/requests/logout/accept?logout_challenge=3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931"));
    }

    @Test
    void continueSession_WhenLogoutAccepted_ReturnsRedirect() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/reject?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(201)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", "https://clienta.localhost:11443/logout");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "......", "00000000-1111-2222-3333-4444444444445", "00000000-1111-2222-3333444444444444", "3C3EF85A-3D8B-4EA2-BB53-B66BC5BD1931"})
    void continueSession_WhenLogoutChallengeInvalid_ThrowsUserInputError(String logoutChallenge) throws IOException {

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", logoutChallenge)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        verify(errorHandler).handleBindException(exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("continueSession.logoutChallenge: must match \"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$\""));
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "blank"})
    void continueSession_WhenFetchLogoutRequestInfoReturnsInvalidPostLogoutRedirectUri_ThrowsUserInputError(String postLogoutRedirectUri) throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_%s_post_logout_redirect_uri.json".formatted(postLogoutRedirectUri))));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                startsWith("Invalid post logout redirect URI"));
    }

    @Test
    void continueSession_WhenFetchLogoutRequestInfoRespondsWith404_ThrowsUserInputError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("404 Not Found from GET https://hydra.localhost:9000/oauth2/auth/requests/logout?logout_challenge=3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931"));
    }

    @Test
    void continueSession_WhenFetchLogoutRequestInfoRespondsWith410_ThrowsUserInputError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(410)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("410 Gone from GET https://hydra.localhost:9000/oauth2/auth/requests/logout?logout_challenge=3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931"));
    }

    @Test
    void continueSession_WhenFetchLogoutRequestInfoRespondsWith500_ThrowsTechnicalGeneralError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("500 Internal Server Error from GET https://hydra.localhost:9000/oauth2/auth/requests/logout?logout_challenge=3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931"));
    }

    @Test
    void continueSession_WhenRejectLogoutRespondsWith404_ThrowsUserInputError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/reject?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("404 Not Found from PUT https://hydra.localhost:9000/oauth2/auth/requests/logout/reject?logout_challenge=3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931"));
    }

    @Test
    void continueSession_WhenRejectLogoutRespondsWith500_ThrowsTechnicalGeneralError() throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/reject?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("500 Internal Server Error from PUT https://hydra.localhost:9000/oauth2/auth/requests/logout/reject?logout_challenge=3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931"));
    }
}