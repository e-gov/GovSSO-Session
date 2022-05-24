package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import io.restassured.RestAssured;
import io.restassured.builder.ResponseSpecBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.notMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.putRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class ConsentInitControllerTest extends BaseTest {
    public static final String MOCK_CONSENT_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";

    @BeforeEach
    public void setupExpectedResponseSpec() {
        RestAssured.responseSpecification = new ResponseSpecBuilder()
                .expectHeaders(EXPECTED_RESPONSE_HEADERS_WITH_CORS).build();
    }

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

        assertErrorIsLogged("User input exception: consentInit.consentChallenge: must match \"^[a-f0-9]{32}$\"");
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

        assertErrorIsLogged("User input exception: Required request parameter 'consent_challenge' for method parameter type String is not present");
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

        assertErrorIsLogged("Duplicate parameters not allowed in request. Found multiple parameters with name: consent_challenge");
    }

    @Test
    void consentInit_WhenAcceptConsentIsSuccessful_RedirectsWithIdTokenWithoutPhone() {

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

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .withRequestBody(notMatching(".*\"phone_number\":\"12345\",\"phone_number_verified\":true.*")));
    }

    @Test
    void consentInit_WhenAcceptConsentIsSuccessfulWithPhoneNumber_RedirectsWithIdTokenIncludingPhone() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request_scope_with_phone_idtoken_with_phone.json")));

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

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .withRequestBody(containing("\"phone_number\":\"12345\",\"phone_number_verified\":true")));
    }

    @Test
    void consentInit_WhenAcceptConsentIsSuccessfulWithScopePhoneAndWithoutIdtokenPhone_RedirectsWithIdTokenWithoutPhone() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request_scope_with_phone_idtoken_without_phone.json")));

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

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .withRequestBody(notMatching(".*\"phone_number\":\"12345\",\"phone_number_verified\":true.*")));
    }

    @Test
    void consentInit_WhenAcceptConsentIsSuccessfulWithoutScopePhoneAndWithIdtokenPhone_RedirectsWithIdTokenWithoutPhone() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request_scope_without_phone_idtoken_with_phone.json")));

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

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .withRequestBody(notMatching(".*\"phone_number\":\"12345\",\"phone_number_verified\":true.*")));
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

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consent request info --> 404 Not Found from GET");
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

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consent request info --> 410 Gone from GET");
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

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consent request info --> 500 Internal Server Error from GET");
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

        assertErrorIsLogged("Unexpected error: 500 Internal Server Error from PUT");
    }
}
