package ee.ria.govsso.session.controller;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.service.tara.TaraService;
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
class ConsentInitControllerTest extends BaseTest {

    public static final String MOCK_CONSENT_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";

    private final SessionRepository<MapSession> sessionRepository;
    private final TaraService taraService;

    @ParameterizedTest
    @ValueSource(strings = {"", "......", "123456789012345678901234567890123456789012345678900"})
    void consentInit_WhenConsentChallengeInvalid_ThrowsUserInputError(String consentChallenge) {

        given()
                .param("consent_challenge", consentChallenge)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void consentInit_WhenConsentChallengeParamIsMissing_ThrowsUserInputError() {
        given()
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void consentInit_WhenConsentChallengeParamIsDuplicate_ThrowsUserInputError() {
        given()
                .param("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .param("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void consentInit_WhenAcceptConsentIsSuccessful_Redirects() {

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        String sessionId = createSession();

        given()
                .param("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .when()
                .sessionId("SESSION", sessionId)
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));
    }

    @Test
    void consentInit_WhenAcceptConsentRespondsWith500_ThrowsTechnicalGeneralError() {

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        String sessionId = createSession();

        given()
                .param("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .when()
                .sessionId("SESSION", sessionId)
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @SneakyThrows
    private String createSession() {
        MapSession session = sessionRepository.createSession();
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        String state = authenticationRequest.getState().getValue();
        String nonce = authenticationRequest.getNonce().getValue();
        SsoSession ssoSession = new SsoSession();
        ssoSession.setTaraAuthenticationRequestState(state);
        ssoSession.setTaraAuthenticationRequestNonce(nonce);
        session.setAttribute(SSO_SESSION, ssoSession);
        sessionRepository.save(session);
        return Base64.getEncoder().withoutPadding().encodeToString(session.getId().getBytes());
    }
}
