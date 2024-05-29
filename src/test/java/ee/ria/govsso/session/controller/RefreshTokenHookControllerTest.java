package ee.ria.govsso.session.controller;

import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.configuration.properties.XRoadConfigurationProperties;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookRequest;
import ee.ria.govsso.session.service.hydra.RepresenteeRequestStatus;
import ee.ria.govsso.session.service.paasuke.PaasukeHeaders;
import ee.ria.govsso.session.xroad.XRoadHeaders;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.controller.RefreshTokenHookController.TOKEN_REFRESH_REQUEST_MAPPING;
import static ee.ria.govsso.session.service.hydra.RepresenteeList.RepresenteeListRequestStatus.REPRESENTEE_LIST_CURRENT;
import static ee.ria.govsso.session.service.hydra.RepresenteeList.RepresenteeListRequestStatus.SERVICE_NOT_AVAILABLE;
import static ee.ria.govsso.session.util.wiremock.ExtraWiremockMatchers.isUuid;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class RefreshTokenHookControllerTest extends BaseTest {

    private static final String SESSION_ID = "e56cbaf9-81e9-4473-a733-261e8dd38e95";
    private static final String CLIENT_ID = "client-a";
    private static final String INSTITUTION_ID = "EE12345678";
    private final XRoadConfigurationProperties xRoadConfigurationProperties;

    @Test
    void tokenRefresh_WhenHydraRespondsWith404_ThrowsTechnicalGeneralError() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid"));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 404 Not Found from GET https://hydra.localhost:9000/admin/oauth2/auth/sessions/consent?subject");
    }

    @Test
    void tokenRefresh_WhenConsentsAreMissing_ThrowsTechnicalGeneralError() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid"));
        hookRequest.setSubject("testSubject");

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=testSubject&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_missing.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("SsoException: Consent has expired");
    }

    @Test
    void tokenRefresh_WhenConsentsDontHaveValidClientId_ThrowsTechnicalGeneralError() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, "client-x", List.of("openid"));
        hookRequest.setSubject("testSubject");

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=testSubject&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("SsoException: Consent has expired");
    }

    @Test
    void tokenRefresh_ok() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid"));
        hookRequest.setSubject("testSubject");

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=testSubject&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.id_token.given_name", equalTo("Eesnimi3"))
                .body("session.id_token.family_name", equalTo("Perekonnanimi3"))
                .body("session.id_token.birthdate", equalTo("1961-07-12"))
                .body("session.id_token.sid", equalTo("e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .body("session.refresh_remember_for", equalTo(true))
                .body("session.remember_for", equalTo(900))
                .body("session.refresh_consent_remember_for", equalTo(true))
                .body("session.consent_remember_for", equalTo(900))
                .body("session.access_token.acr", equalTo("high"))
                .body("session.access_token.amr", equalTo(List.of("mID")))
                .body("session.access_token.given_name", equalTo("Eesnimi3"))
                .body("session.access_token.family_name", equalTo("Perekonnanimi3"))
                .body("session.access_token.birthdate", equalTo("1961-07-12"))
                .body("session.access_token.phone_number", nullValue())
                .body("session.access_token.phone_number_verified", nullValue());
    }

    @Test
    void tokenRefresh_whenPhoneScopeIsRequested_ok() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid", "phone"));
        hookRequest.setSubject("testSubject");

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=testSubject&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.id_token.given_name", equalTo("Eesnimi3"))
                .body("session.id_token.family_name", equalTo("Perekonnanimi3"))
                .body("session.id_token.birthdate", equalTo("1961-07-12"))
                .body("session.id_token.sid", equalTo("e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .body("session.id_token.phone_number", equalTo("12345"))
                .body("session.id_token.phone_number_verified", equalTo(true))
                .body("session.refresh_remember_for", equalTo(true))
                .body("session.remember_for", equalTo(900))
                .body("session.refresh_consent_remember_for", equalTo(true))
                .body("session.consent_remember_for", equalTo(900))
                .body("session.access_token.acr", equalTo("high"))
                .body("session.access_token.amr", equalTo(List.of("mID")))
                .body("session.access_token.given_name", equalTo("Eesnimi3"))
                .body("session.access_token.family_name", equalTo("Perekonnanimi3"))
                .body("session.access_token.birthdate", equalTo("1961-07-12"))
                .body("session.access_token.phone_number", equalTo("12345"))
                .body("session.access_token.phone_number_verified", equalTo(true));
    }

    @Test
    void tokenRefresh_whenSessionIdIsMissing_throwsTechnicalGeneralError() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(null, CLIENT_ID, List.of("openid"));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("SsoException: Hydra session was not found");
    }

    @Test
    void tokenRefresh_whenAccessTokenStrategyIsOpaque_ok() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid"));
        hookRequest.setSubject("testSubject");

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=testSubject&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_access_token_strategy_opaque.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.id_token.given_name", equalTo("Eesnimi3"))
                .body("session.id_token.family_name", equalTo("Perekonnanimi3"))
                .body("session.id_token.birthdate", equalTo("1961-07-12"))
                .body("session.id_token.sid", equalTo("e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .body("session.refresh_remember_for", equalTo(true))
                .body("session.remember_for", equalTo(900))
                .body("session.refresh_consent_remember_for", equalTo(true))
                .body("session.consent_remember_for", equalTo(900))
                .body("session.access_token", nullValue());
    }

    @ParameterizedTest
    @ValueSource(strings = {"representee.ABC123", "openid representee.ABC123", "representee.ABC123 openid", "representee.* representee.ABC123", "representee.ABC123 representee.*"})
    void tokenRefresh_whenRepresenteeScopeProvided_ok(String scopes) {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid", "representee.*"));
        hookRequest.setSubject("Isikukood3");
        hookRequest.setRequestedScopes(Arrays.asList(scopes.split(" ")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo("Isikukood3"))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .withHeader(PaasukeHeaders.INSTITUTION, WireMock.equalTo(INSTITUTION_ID))
                .withHeader(PaasukeHeaders.CLIENT_ID, WireMock.equalTo(CLIENT_ID))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/paasuke/getRepresenteeDelegateMandates/ABC123_Isikukood3_ns_AGENCY-Q.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.id_token.representee.status", equalTo(RepresenteeRequestStatus.REQUESTED_REPRESENTEE_CURRENT.name()))
                .body("session.id_token.representee.type", equalTo("LEGAL_PERSON"))
                .body("session.id_token.representee.sub", equalTo("ABC123"))
                .body("session.id_token.representee.given_name", nullValue())
                .body("session.id_token.representee.family_name", nullValue())
                .body("session.id_token.representee.name", equalTo("Sukk ja Saabas OÜ"))
                .body("session.id_token.representee.mandates[0].role", equalTo("BR_REPRIGHT:JUHL"))
                .body("session.id_token.representee.mandates[1].role", equalTo("AGENCY-Q:Edit.submit"));
    }

    @Test
    /* TODO: Due to available test data, the returned representee will be "ASD123" instead of the requested "1".
     *       Either create proper test data or remove this test and replace it with a unit test. */
    void tokenRefresh_whenRepresenteeIdSingleCharacter_ok() {
        RefreshTokenHookRequest hookRequest =
                createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid", "representee.*"));
        hookRequest.setSubject("Isikukood3");
        hookRequest.setRequestedScopes(List.of("representee.1"));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/representees/1/delegates/Isikukood3/mandates?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo("Isikukood3"))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .withHeader(PaasukeHeaders.INSTITUTION, WireMock.equalTo(INSTITUTION_ID))
                .withHeader(PaasukeHeaders.CLIENT_ID, WireMock.equalTo(CLIENT_ID))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/paasuke/getRepresenteeDelegateMandates/ABC123_Isikukood3_ns_AGENCY-Q.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.id_token.representee.status", equalTo(RepresenteeRequestStatus.REQUESTED_REPRESENTEE_CURRENT.name()))
                .body("session.id_token.representee.type", equalTo("LEGAL_PERSON"))
                .body("session.id_token.representee.sub", equalTo("ABC123"))
                .body("session.id_token.representee.given_name", nullValue())
                .body("session.id_token.representee.family_name", nullValue())
                .body("session.id_token.representee.name", equalTo("Sukk ja Saabas OÜ"))
                .body("session.id_token.representee.mandates[0].role", equalTo("BR_REPRIGHT:JUHL"))
                .body("session.id_token.representee.mandates[1].role", equalTo("AGENCY-Q:Edit.submit"));
    }

    @Test
        /* TODO: Due to available test data, the returned representee will be "ASD123" instead of the requested "ISIKUKOOD3".
         *       Either create proper test data or remove this test and replace it with a unit test. */
    void tokenRefresh_whenRepresenteeIdHasOnlyCaseDifference_ok() {
        RefreshTokenHookRequest hookRequest =
                createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid", "representee.*"));
        hookRequest.setSubject("Isikukood3");
        hookRequest.setRequestedScopes(List.of("representee.ISIKUKOOD3"));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/representees/ISIKUKOOD3/delegates/Isikukood3/mandates?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo("Isikukood3"))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .withHeader(PaasukeHeaders.INSTITUTION, WireMock.equalTo(INSTITUTION_ID))
                .withHeader(PaasukeHeaders.CLIENT_ID, WireMock.equalTo(CLIENT_ID))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/paasuke/getRepresenteeDelegateMandates/ABC123_Isikukood3_ns_AGENCY-Q.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.id_token.representee.status", equalTo(RepresenteeRequestStatus.REQUESTED_REPRESENTEE_CURRENT.name()))
                .body("session.id_token.representee.type", equalTo("LEGAL_PERSON"))
                .body("session.id_token.representee.sub", equalTo("ABC123"))
                .body("session.id_token.representee.given_name", nullValue())
                .body("session.id_token.representee.family_name", nullValue())
                .body("session.id_token.representee.name", equalTo("Sukk ja Saabas OÜ"))
                .body("session.id_token.representee.mandates[0].role", equalTo("BR_REPRIGHT:JUHL"))
                .body("session.id_token.representee.mandates[1].role", equalTo("AGENCY-Q:Edit.submit"));
    }

    @Test
    void tokenRefresh_whenAuthenticatedUserIsNotAllowedToRepresentRepresentee_representeeIsOmitted() {
        RefreshTokenHookRequest hookRequest =
                createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid", "representee.*"));
        hookRequest.setSubject("Isikukood3");
        hookRequest.setRequestedScopes(List.of("representee.ABC123"));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo("Isikukood3"))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .withHeader(PaasukeHeaders.INSTITUTION, WireMock.equalTo(INSTITUTION_ID))
                .withHeader(PaasukeHeaders.CLIENT_ID, WireMock.equalTo(CLIENT_ID))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/paasuke/getRepresenteeDelegateMandates/ABC123_Isikukood3_ns_AGENCY-Q__no_mandates.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.access_token.representee.status", equalTo(RepresenteeRequestStatus.REQUESTED_REPRESENTEE_NOT_ALLOWED.name()))
                .body("session.access_token.representee.type", nullValue())
                .body("session.access_token.representee.sub", nullValue())
                .body("session.access_token.representee.given_name", nullValue())
                .body("session.access_token.representee.family_name", nullValue())
                .body("session.access_token.representee.name", nullValue())
                .body("session.access_token.representee.mandates", nullValue())
                .body("session.id_token.representee.status", equalTo(RepresenteeRequestStatus.REQUESTED_REPRESENTEE_NOT_ALLOWED.name()))
                .body("session.id_token.representee.type", nullValue())
                .body("session.id_token.representee.sub", nullValue())
                .body("session.id_token.representee.given_name", nullValue())
                .body("session.id_token.representee.family_name", nullValue())
                .body("session.id_token.representee.name", nullValue())
                .body("session.id_token.representee.mandates", nullValue());

        assertErrorIsLogged("User is not allowed to represent provided representee");
    }

    @Test
    void tokenRefresh_whenMandatesRequestFails_representeeIsOmitted() {
        RefreshTokenHookRequest hookRequest =
                createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid", "representee.*"));
        hookRequest.setSubject("Isikukood3");
        hookRequest.setRequestedScopes(List.of("representee.ABC123"));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo("Isikukood3"))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .withHeader(PaasukeHeaders.INSTITUTION, WireMock.equalTo(INSTITUTION_ID))
                .withHeader(PaasukeHeaders.CLIENT_ID, WireMock.equalTo(CLIENT_ID))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.access_token.representee.status", equalTo(RepresenteeRequestStatus.SERVICE_NOT_AVAILABLE.name()))
                .body("session.access_token.representee.type", nullValue())
                .body("session.access_token.representee.sub", nullValue())
                .body("session.access_token.representee.given_name", nullValue())
                .body("session.access_token.representee.family_name", nullValue())
                .body("session.access_token.representee.name", nullValue())
                .body("session.access_token.representee.mandates", nullValue())
                .body("session.id_token.representee.status", equalTo(RepresenteeRequestStatus.SERVICE_NOT_AVAILABLE.name()))
                .body("session.id_token.representee.type", nullValue())
                .body("session.id_token.representee.sub", nullValue())
                .body("session.id_token.representee.given_name", nullValue())
                .body("session.id_token.representee.family_name", nullValue())
                .body("session.id_token.representee.name", nullValue())
                .body("session.id_token.representee.mandates", nullValue());

        assertErrorIsLogged("Pääsuke fetchMandates request failed with HTTP error");
    }

    @Test
    void tokenRefresh_whenRequestedScopesIsAnEmptyList_representeeIsOmitted() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid"));
        hookRequest.setSubject("testSubject");
        hookRequest.setRequestedScopes(List.of());

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=testSubject&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.access_token.representee", nullValue())
                .body("session.id_token.representee", nullValue());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"openid"})
    void tokenRefresh_whenRequestedScopesIsWithoutRepresentee_RepresenteeIsNotAddedToIdTokenOrAccessToken(String scope) {
        List<String> scopesList = new ArrayList<>();
        scopesList.add(scope);
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid"));
        hookRequest.setSubject("testSubject");
        hookRequest.setRequestedScopes(scopesList);

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=testSubject&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.access_token.representee", nullValue())
                .body("session.id_token.representee", nullValue());
    }

    @Test
    void tokenRefresh_whenRepresenteeScopeSubjectIsNotAtLeast1CharacterLong_ThrowsUserInputError() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid", "phone", "representee.*"));
        hookRequest.setSubject("testSubject");
        hookRequest.setRequestedScopes(List.of("representee."));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=testSubject&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400);

        assertErrorIsLogged("SsoException: The subject length in the representee scope must be at least 1 character or longer");
    }

    @Test
    void tokenRefresh_whenRepresenteeSubjectEqualsAuthenticatedUserSubject_RepresenteeIsNotAddedToIdTokenOrAccessToken() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid", "phone", "representee.*"));
        hookRequest.setSubject("Isikukood3");
        hookRequest.setRequestedScopes(List.of("representee.Isikukood3"));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.access_token.representee", nullValue())
                .body("session.id_token.representee", nullValue());
    }

    @Test
    void tokenRefresh_whenAccessTokenStrategyIsOpaque_RepresenteeIsNotAddedToAccessToken() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid", "phone", "representee.*"));
        hookRequest.setSubject("Isikukood3");
        hookRequest.setRequestedScopes(List.of("representee.ABC123"));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_access_token_strategy_opaque.json")));

        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo("Isikukood3"))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .withHeader(PaasukeHeaders.INSTITUTION, WireMock.equalTo(INSTITUTION_ID))
                .withHeader(PaasukeHeaders.CLIENT_ID, WireMock.equalTo(CLIENT_ID))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/paasuke/getRepresenteeDelegateMandates/ABC123_Isikukood3_ns_AGENCY-Q.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.access_token.representee", nullValue())
                .body("session.id_token.representee.status", equalTo(RepresenteeRequestStatus.REQUESTED_REPRESENTEE_CURRENT.name()))
                .body("session.id_token.representee.type", equalTo("LEGAL_PERSON"))
                .body("session.id_token.representee.sub", equalTo("ABC123"))
                .body("session.id_token.representee.given_name", nullValue())
                .body("session.id_token.representee.family_name", nullValue())
                .body("session.id_token.representee.name", equalTo("Sukk ja Saabas OÜ"))
                .body("session.id_token.representee.mandates[0].role", equalTo("BR_REPRIGHT:JUHL"))
                .body("session.id_token.representee.mandates[1].role", equalTo("AGENCY-Q:Edit.submit"));
    }

    @Test
    void tokenRefresh_whenMultipleRepresenteesAreRequested_ThrowsUserInvalidOidcRequestError() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid", "representee.*"));
        hookRequest.setRequestedScopes(List.of("openid", "representee.A", "representee.B"));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=testSubject&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400);

        assertErrorIsLogged("SsoException: Refresh token hook request must not contain multiple representee scopes with subjects.");
    }

    @Test
    void tokenRefresh_whenRepresenteeScopeIsRequestedButNotGranted_ThrowsUserInvalidOidcRequestError() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid"));
        hookRequest.setRequestedScopes(List.of("openid", "representee.A"));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=testSubject&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400);

        assertErrorIsLogged("SsoException: Refresh token hook request must not contain a representee scope with subject when 'representee.*' is not in the list of granted scopes.");
    }



    @ParameterizedTest
    @ValueSource(strings = {"phone", "REPRESENTEE.X", "OPENID"})
    void tokenRefresh_whenScopeIsRequestedButNotGranted_ThrowsUserInvalidOidcRequestError(String scope) {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid"));
        hookRequest.setRequestedScopes(List.of(scope));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=testSubject&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400);

        assertErrorIsLogged("SsoException: Refresh token hook request must not contain a requested scope that is not in the list of granted scopes.");
    }

    @Test
    void tokenRefresh_whenRepresenteeListIsRequested_representeeListIsAddedToIdToken() {
        RefreshTokenHookRequest hookRequest =
                createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid", "representee_list"));
        hookRequest.setSubject("Isikukood3");
        hookRequest.setRequestedScopes(List.of("representee_list"));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/delegates/Isikukood3/representees?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo("Isikukood3"))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .withHeader(PaasukeHeaders.INSTITUTION, WireMock.equalTo(INSTITUTION_ID))
                .withHeader(PaasukeHeaders.CLIENT_ID, WireMock.equalTo(CLIENT_ID))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/paasuke/getDelegateRepresentees/Isikukood3_ns_AGENCY-Q.json")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.id_token.representee_list.status", equalTo(REPRESENTEE_LIST_CURRENT.name()))
                .body("session.id_token.representee_list.list[0].type", equalTo("LEGAL_PERSON"))
                .body("session.id_token.representee_list.list[0].sub", equalTo("EE12345678"))
                .body("session.id_token.representee_list.list[0].name", equalTo("Sukk ja Saabas OÜ"))
                .body("session.id_token.representee_list.list[1].type", equalTo("NATURAL_PERSON"))
                .body("session.id_token.representee_list.list[1].sub", equalTo("EE47101010033"))
                .body("session.id_token.representee_list.list[1].given_name", equalTo("Mari-Liis"))
                .body("session.id_token.representee_list.list[1].family_name", equalTo("Männik"))
                .body("session.access_token.representee_list", nullValue());
    }

    @Test
    void tokenRefresh_whenRepresenteeListIsEmpty_emptyRepresenteeListIsAddedToIdToken() {
        RefreshTokenHookRequest hookRequest =
                createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid", "representee_list"));
        hookRequest.setSubject("Isikukood3");
        hookRequest.setRequestedScopes(List.of("representee_list"));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/delegates/Isikukood3/representees?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo("Isikukood3"))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .withHeader(PaasukeHeaders.INSTITUTION, WireMock.equalTo(INSTITUTION_ID))
                .withHeader(PaasukeHeaders.CLIENT_ID, WireMock.equalTo(CLIENT_ID))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("[]")));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.id_token.representee_list.list", equalTo(Collections.emptyList()))
                .body("session.id_token.representee_list.status", equalTo(REPRESENTEE_LIST_CURRENT.name()))
                .body("session.access_token.representee_list", nullValue());
    }

    @Test
    void tokenRefresh_whenRepresenteeListRequestFails_RepresenteeListIsNotAddedToIdToken() {
        RefreshTokenHookRequest hookRequest =
                createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openid", "representee_list"));
        hookRequest.setSubject("Isikukood3");
        hookRequest.setRequestedScopes(List.of("representee_list"));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/delegates/Isikukood3/representees?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo("Isikukood3"))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .withHeader(PaasukeHeaders.INSTITUTION, WireMock.equalTo(INSTITUTION_ID))
                .withHeader(PaasukeHeaders.CLIENT_ID, WireMock.equalTo(CLIENT_ID))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body("session.id_token.representee_list.status", equalTo(SERVICE_NOT_AVAILABLE.name()))
                .body("session.id_token.representee_list.list", nullValue())
                .body("session.access_token.representee_list", nullValue());

        assertErrorIsLogged("Pääsuke fetchRepresentees request failed with HTTP error");
    }

    private RefreshTokenHookRequest createRefreshTokenHookRequest(String sid, String clientId, List<String> scopes) {
        RefreshTokenHookRequest hookRequest = new RefreshTokenHookRequest();
        RefreshTokenHookRequest.Session session = new RefreshTokenHookRequest.Session();
        RefreshTokenHookRequest.IdToken idToken = new RefreshTokenHookRequest.IdToken();
        RefreshTokenHookRequest.IdTokenClaims idTokenClaims = new RefreshTokenHookRequest.IdTokenClaims();
        RefreshTokenHookRequest.Ext ext = new RefreshTokenHookRequest.Ext();
        if (sid != null) {
            ext.setSid(sid);
        }
        idTokenClaims.setExt(ext);

        idToken.setIdTokenClaims(idTokenClaims);
        session.setIdToken(idToken);
        hookRequest.setSession(session);
        hookRequest.setGrantedScopes(scopes);
        hookRequest.setClientId(clientId);
        return hookRequest;
    }
}
