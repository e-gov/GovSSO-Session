package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.session.SsoSession;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.MapSession;
import org.springframework.session.SessionRepository;

import java.util.Base64;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class AuthConsentControllerTest extends BaseTest {

    public static final String MOCK_CONSENT_CHALLENGE = "abcdefg098AAdsCC";

    private final SessionRepository<MapSession> sessionRepository;

    @ParameterizedTest
    @ValueSource(strings = {"", "......"})
    void authConsent_consentChallenge_EmptyValue_and_InvalidValue(String consentChallenge) {

        given()
                .param("consent_challenge", consentChallenge)
                .when()
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authConsent.consentChallenge: only characters and numbers allowed"))
                .body("error", equalTo("Bad Request"));
    }

    @Test
    void authConsent_consentChallenge_ParamMissing() {
        given()
                .when()
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required request parameter 'consent_challenge' for method parameter type String is not present"))
                .body("error", equalTo("Bad Request"));
    }

    @Test
    void authConsent_consentChallenge_InvalidLength() {
        given()
                .param("consent_challenge", "123456789012345678901234567890123456789012345678900")
                .when()
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authConsent.consentChallenge: size must be between 0 and 50"))
                .body("error", equalTo("Bad Request"));
    }

    @Test
    void authConsent_ok() {

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_accept_consent_response.json")));

        String sessionId = createSession();

        given()
                .param("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .when()
                .sessionId("SESSION", sessionId)
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));
    }

    @Test
    void authConsent_HydraRespondsWithError() {

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_accept_consent_response.json")));

        String sessionId = createSession();

        given()
                .param("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .when()
                .sessionId("SESSION", sessionId)
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(500);
    }

    @SneakyThrows
    private String createSession() {
        MapSession session = sessionRepository.createSession();
        SsoSession ssoSession = new SsoSession();
        session.setAttribute(SSO_SESSION, ssoSession);
        sessionRepository.save(session);

        return Base64.getEncoder().withoutPadding().encodeToString(session.getId().getBytes());
    }
}
