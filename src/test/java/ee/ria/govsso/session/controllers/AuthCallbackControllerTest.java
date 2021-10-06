package ee.ria.govsso.session.controllers;

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
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.controllers.AuthCallbackController.CALLBACK_REQUEST_MAPPING;
import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;
import static io.restassured.RestAssured.given;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class AuthCallbackControllerTest extends BaseTest {

    private final SessionRepository<MapSession> sessionRepository;

    @Test
    void authCallback_Ok() {

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_idToken_response.json")));

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_accept_login_response.json")));

        String sessionId = createSession();

        given()
                .param("code", "testcode")
                .param("state", "teststate")
                .param("nonce", "testnonce")
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/url/test"))
                .extract().cookie("SESSION");
    }

    @Test
    void authCallback_TaraRespondsWithError() {

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_idToken_response.json")));

        String sessionId = createSession();

        given()
                .param("code", "testcode")
                .param("state", "teststate")
                .param("nonce", "testnonce")
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500);
    }

    @Test
    void authCallback_HydraRespondsWithError() {

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_idToken_response.json")));

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge"))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_accept_login_response.json")));

        String sessionId = createSession();

        given()
                .param("code", "testcode")
                .param("state", "teststate")
                .param("nonce", "testnonce")
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500);
    }

    private String createSession() {
        MapSession session = sessionRepository.createSession();
        SsoSession ssoSession = new SsoSession();
        SsoSession.LoginRequestInfo lri = new SsoSession.LoginRequestInfo();
        SsoSession.Client client = new SsoSession.Client();
        client.setRedirectUris(new String[]{"some/test/url"});
        lri.setClient(client);
        ssoSession.setLoginRequestInfo(lri);
        session.setAttribute(SSO_SESSION, ssoSession);
        sessionRepository.save(session);

        return Base64.getEncoder().withoutPadding().encodeToString(session.getId().getBytes());
    }
}
