package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN;
import static org.springframework.http.HttpHeaders.ORIGIN;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class ConsentInitControllerTest extends BaseTest {
    public static final String MOCK_CONSENT_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";

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

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        given()
                .param("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));
    }

    @Test
    void consentInit_WhenGetConsentRequestInfoRespondswith404_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .param("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void consentInit_WhenGetConsentRequestInfoRespondswith410_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(410)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .param("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void consentInit_WhenGetConsentRequestInfoRespondswith500_ThrowsTechnicalGeneralError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .param("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void consentInit_WhenAcceptConsentRespondsWith500_ThrowsTechnicalGeneralError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .param("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void consentInit_WhenOriginHeaderIsSet_SetsCorsResponseHeaders() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        given()
                .param("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .header(ORIGIN, "https://clienta.localhost:11443")
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"))
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "https://clienta.localhost:11443")
                .header(ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
    }
}
