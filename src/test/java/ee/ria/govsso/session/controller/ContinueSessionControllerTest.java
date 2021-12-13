package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.session.SsoSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.MapSession;
import org.springframework.session.SessionRepository;

import java.util.Base64;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.controller.ContinueSessionController.AUTH_VIEW_REQUEST_MAPPING;
import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class ContinueSessionControllerTest extends BaseTest {

    private static final String TEST_LOGIN_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";
    private final SessionRepository<MapSession> sessionRepository;

    @Test
    void loginInit_WhenFetchLoginRequestInfoIsSuccessful_CreatesSessionAndRedirects() {

        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .sessionId("SESSION", sessionId)
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("/auth/login/test"));
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoSubjectIsEmpty_ThrowsUserInputError() {

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
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
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
