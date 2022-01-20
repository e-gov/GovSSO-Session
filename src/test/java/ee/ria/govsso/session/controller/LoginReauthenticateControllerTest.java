package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.session.SsoSession;
import io.restassured.matcher.RestAssuredMatchers;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.MapSession;
import org.springframework.session.SessionRepository;

import java.util.Base64;
import java.util.Date;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.controller.LoginReauthenticateController.LOGIN_REAUTHENTICATE_REQUEST_MAPPING;
import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class LoginReauthenticateControllerTest extends BaseTest {

    private static final String TEST_LOGIN_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";
    private final SessionRepository<MapSession> sessionRepository;

    @Test
    void loginInit_WhenLoginReauthenticateIsSuccessful_Redirects() {
        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(204)));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/login/e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(204)));

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/reject?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_reject.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .sessionId("SESSION", sessionId)
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.equalTo("http://localhost:14444/oauth2/auth?scope=openid&prompt=consent&response_type=code&client_id=openIdDemo&redirect_uri=https://localhost:11443/oauth/response&state=049d71ea-30cd-4a74-8dcd-47156055d364&nonce=5210b42a-2362-420b-bb81-54796da8c814&ui_locales=et"));
    }

    @Test
    void loginInit_WhenSsoSessionLoginRequestInfoIsMissing_ThrowsUserInputOrExpiredError() {
        String sessionId = createSession(new SsoSession());

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .sessionId("SESSION", sessionId)
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT_OR_EXPIRED"));
    }

    @Test
    void loginInit_WhenDeleteConsentReturns400_ThrowsTechnicalGeneralError() {
        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(400)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .sessionId("SESSION", sessionId)
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void loginInit_WhenLoginRequestInfoSubjectEmpty_ThrowsTechnicalGeneralError() {
        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .sessionId("SESSION", sessionId)
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenDeleteLoginReturns400_ThrowsTechnicalGeneralError() {
        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(204)));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/login/e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(400)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .sessionId("SESSION", sessionId)
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void loginInit_WhenRejectLoginReturns404_ThrowsUserInputError() {
        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(204)));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/login/e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(204)));

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/reject?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .sessionId("SESSION", sessionId)
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenRejectLoginReturns400_ThrowsTechnicalGeneralError() {
        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(204)));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/login/e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(204)));

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/reject?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(400)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .sessionId("SESSION", sessionId)
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void loginInit_IfHydraSessionCookieExists_HydraSessionCookieIsDeleted() {
        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(204)));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/login/e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(204)));

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/reject?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_reject.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .cookie("oauth2_authentication_session_insecure", "test1234")
                .sessionId("SESSION", sessionId)
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .cookie("oauth2_authentication_session_insecure", RestAssuredMatchers.detailedCookie().maxAge(0).value("test1234").path("/").expiryDate(new Date(10000)));
    }

    private SsoSession createSsoSession() {
        SsoSession ssoSession = new SsoSession();
        ssoSession.setLoginChallenge(TEST_LOGIN_CHALLENGE);
        return ssoSession;
    }

    private String createSession(SsoSession ssoSession) {
        MapSession session = sessionRepository.createSession();
        session.setAttribute(SSO_SESSION, ssoSession);
        sessionRepository.save(session);
        return Base64.getEncoder().withoutPadding().encodeToString(session.getId().getBytes());
    }
}
