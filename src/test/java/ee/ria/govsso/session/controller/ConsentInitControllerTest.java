package ee.ria.govsso.session.controller;

import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.configuration.properties.XRoadConfigurationProperties;
import ee.ria.govsso.session.service.paasuke.PaasukeHeaders;
import ee.ria.govsso.session.xroad.XRoadHeaders;
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
import static ee.ria.govsso.session.service.hydra.RepresenteeList.RepresenteeListRequestStatus.REPRESENTEE_LIST_CURRENT;
import static ee.ria.govsso.session.service.hydra.RepresenteeList.RepresenteeListRequestStatus.SERVICE_NOT_AVAILABLE;
import static ee.ria.govsso.session.util.wiremock.ExtraWiremockMatchers.isUuid;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class ConsentInitControllerTest extends BaseTest {
    public static final String TEST_CONSENT_CHALLENGE = "aaabbbcccdddeeefff00011122233344";
    private final XRoadConfigurationProperties xRoadConfigurationProperties;

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
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
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

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .withRequestBody(containing("{\"id_token\":{\"given_name\":\"Eesnimi3\",\"family_name\":\"Perekonnanimi3\",\"birthdate\":\"1961-07-12\"}")));
    }

    @Test
    void consentInit_WhenAcceptConsentIsSuccessfulWithAccessTokenStrategyJwt_RedirectsWithAccessToken() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request_with_access_token.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .withRequestBody(containing("\"access_token\":{\"acr\":\"high\",\"amr\":[\"mID\"],\"given_name\":\"Eesnimi3\",\"family_name\":\"Perekonnanimi3\",\"birthdate\":\"1961-07-12\""))
                .withRequestBody(containing("\"grant_access_token_audience\":[\"https://test1\"]")));
    }

    @Test
    void consentInit_WhenAcceptConsentIsSuccessfulWithRequestedAccessTokenAudience_RedirectsWithAccessToken() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request_with_access_token_with_requested_access_token_audience.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .withRequestBody(containing("\"access_token\":{\"acr\":\"high\",\"amr\":[\"mID\"],\"given_name\":\"Eesnimi3\",\"family_name\":\"Perekonnanimi3\",\"birthdate\":\"1961-07-12\""))
                .withRequestBody(containing("\"grant_access_token_audience\":[\"https://test2\"]")));
    }

    @Test
    void consentInit_WhenAcceptConsentIsSuccessfulWithPhoneNumberAndWithAccessTokenStrategyJwt_RedirectsWithAccessToken() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request_with_phone_idtoken_with_phone_access_token.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .withRequestBody(containing("\"access_token\":{\"acr\":\"high\",\"amr\":[\"mID\"],\"given_name\":\"Eesnimi3\",\"family_name\":\"Perekonnanimi3\",\"birthdate\":\"1961-07-12\"," +
                        "\"phone_number\":\"12345\",\"phone_number_verified\":true")));
    }

    @Test
    void consentInit_WhenAcceptConsentIsSuccessfulWithAccessTokenStrategyNotJwt_RedirectsWithoutAccessToken() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request_with_access_token_not_jwt.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .withRequestBody(containing("\"access_token\":null")));
    }

    @Test
    void consentInit_WhenAcceptConsentIsSuccessfulWithPhoneNumber_RedirectsWithIdTokenIncludingPhone() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request_scope_with_phone_idtoken_with_phone.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .withRequestBody(containing("\"phone_number\":\"12345\",\"phone_number_verified\":true")));
    }

    @Test
    void consentInit_WhenAcceptConsentIsSuccessfulWithScopePhoneAndWithoutIdtokenPhone_RedirectsWithIdTokenWithoutPhone() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request_scope_with_phone_idtoken_without_phone.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .withRequestBody(notMatching(".*\"phone_number\":\"12345\",\"phone_number_verified\":true.*")));
    }

    @Test
    void consentInit_WhenAcceptConsentIsSuccessfulWithoutScopePhoneAndWithIdtokenPhone_RedirectsWithIdTokenWithoutPhone() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request_scope_without_phone_idtoken_with_phone.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .withRequestBody(notMatching(".*\"phone_number\":\"12345\",\"phone_number_verified\":true.*")));
    }

    @Test
    void consentInit_WhenGetConsentRequestInfoRespondswith404_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
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

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(410)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
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

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
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

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("Unexpected error: 500 Internal Server Error from PUT");
    }

    @Test
    void consentInit_WhenAcceptConsentWithRepresenteeListScopeIsSuccessful_RedirectsWithIdTokenWithRepresentees() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request_scope_with_representee_list.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/delegates/Isikukood3/representees?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo("Isikukood3"))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .withHeader(PaasukeHeaders.INSTITUTION, WireMock.equalTo("EE12345678"))
                .withHeader(PaasukeHeaders.CLIENT_ID, WireMock.equalTo("client-a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/paasuke/getDelegateRepresentees/Isikukood3_ns_AGENCY-Q.json")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .withRequestBody(containing("\"representee_list\":{\"status\":\"" + REPRESENTEE_LIST_CURRENT + "\",\"list\":[{\"type\":\"LEGAL_PERSON\",\"sub\":\"EE12345678\",\"name\":\"Sukk ja Saabas OÜ\"},{\"type\":\"NATURAL_PERSON\",\"sub\":\"EE47101010033\",\"given_name\":\"Mari-Liis\",\"family_name\":\"Männik\"}]}"))
                .withRequestBody(containing("\"access_token\":{\"acr\":\"high\",\"amr\":[\"mID\"],\"given_name\":\"Eesnimi3\",\"family_name\":\"Perekonnanimi3\",\"birthdate\":\"1961-07-12\"}")));
    }

    @Test
    void consentInit_whenRepresenteeListRequestFails_RepresenteeListIsNotAddedToIdToken() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request_scope_with_representee_list.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/delegates/Isikukood3/representees?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo("Isikukood3"))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .withHeader(PaasukeHeaders.INSTITUTION, WireMock.equalTo("EE12345678"))
                .withHeader(PaasukeHeaders.CLIENT_ID, WireMock.equalTo("client-a"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .withRequestBody(containing("\"id_token\":{\"given_name\":\"Eesnimi3\",\"family_name\":\"Perekonnanimi3\",\"birthdate\":\"1961-07-12\",\"representee_list\":{\"status\":\"" + SERVICE_NOT_AVAILABLE + "\"}}"))
                .withRequestBody(containing("\"access_token\":{\"acr\":\"high\",\"amr\":[\"mID\"],\"given_name\":\"Eesnimi3\",\"family_name\":\"Perekonnanimi3\",\"birthdate\":\"1961-07-12\"}")));

        assertErrorIsLogged("Pääsuke fetchRepresentees request failed with HTTP error");
    }

    @Test
    void consentInit_whenRepresenteeListIsEmpty_emptyRepresenteeListIsAddedToIdToken() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request_scope_with_representee_list.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));

        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/delegates/Isikukood3/representees?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo("Isikukood3"))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .withHeader(PaasukeHeaders.INSTITUTION, WireMock.equalTo("EE12345678"))
                .withHeader(PaasukeHeaders.CLIENT_ID, WireMock.equalTo("client-a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("[]")));

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .withRequestBody(containing("\"id_token\":{\"given_name\":\"Eesnimi3\",\"family_name\":\"Perekonnanimi3\",\"birthdate\":\"1961-07-12\",\"representee_list\":{\"status\":\"" + REPRESENTEE_LIST_CURRENT + "\",\"list\":[]}}"))
                .withRequestBody(containing("\"access_token\":{\"acr\":\"high\",\"amr\":[\"mID\"],\"given_name\":\"Eesnimi3\",\"family_name\":\"Perekonnanimi3\",\"birthdate\":\"1961-07-12\"}")));
    }
}
