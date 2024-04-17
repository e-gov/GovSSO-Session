package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.controller.RefreshTokenHookController.TOKEN_REFRESH_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class RefreshTokenHookControllerTest extends BaseTest {

    private static final String SESSION_ID = "e56cbaf9-81e9-4473-a733-261e8dd38e95";
    private static final String CLIENT_ID = "client-a";

    @Test
    void tokenRefresh_WhenHydraRespondsWith404_ThrowsTechnicalGeneralError() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openId"));

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
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openId"));
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
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, "client-x", List.of("openId"));
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
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openId"));
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
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openId", "phone"));
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
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(null, CLIENT_ID, List.of("openId"));

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
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openId"));
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
    @ValueSource(strings = {"representee.ABC123", "openid representee.ABC123", "representee.ABC123 openid", "openid representee.A"})
    void tokenRefresh_whenRepresenteeScopeSubjectIsAtLeast1CharacterLong_ok(String scopes) {
        List<String> scopesList = Arrays.asList(scopes.split(" "));
        String requestedRepresentee = scopesList.stream().filter(s -> s.startsWith("representee")).findFirst().get();
        String requestedSubject = StringUtils.substringAfter(requestedRepresentee, ".");
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, scopesList);
        hookRequest.setSubject("ABC123");
        hookRequest.setRequestedScopes(scopesList);

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=ABC123&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
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
                .body("session.access_token.representee.type", equalTo("NATURAL_PERSON"))
                .body("session.access_token.representee.sub", equalTo(requestedSubject))
                .body("session.access_token.representee.given_name", equalTo("First Name"))
                .body("session.access_token.representee.family_name", equalTo("Surname"))
                .body("session.access_token.representee.mandates[0].role", equalTo("role"))
                .body("session.id_token.representee.type", equalTo("NATURAL_PERSON"))
                .body("session.id_token.representee.sub", equalTo(requestedSubject))
                .body("session.id_token.representee.given_name", equalTo("First Name"))
                .body("session.id_token.representee.family_name", equalTo("Surname"))
                .body("session.id_token.representee.mandates[0].role", equalTo("role"));
    }

    @Test
    void tokenRefresh_whenRequestedScopesIsEnEmptyList_RepresenteeIsNotAddedToIdTokenOrAccessToken() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openId"));
        hookRequest.setSubject("testSubject");
        hookRequest.setRequestedScopes(List.of());

        System.out.println(hookRequest);

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
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openId"));
        hookRequest.setSubject("testSubject");
        hookRequest.setRequestedScopes(scopesList);

        System.out.println(hookRequest);

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
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openId", "phone"));
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
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openId", "phone"));
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
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest(SESSION_ID, CLIENT_ID, List.of("openId", "phone"));
        hookRequest.setSubject("testSubject");
        hookRequest.setRequestedScopes(List.of("representee.ABC123"));

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
                .body("session.access_token.representee", nullValue())
                .body("session.id_token.representee.type", equalTo("NATURAL_PERSON"))
                .body("session.id_token.representee.sub", equalTo("ABC123"))
                .body("session.id_token.representee.given_name", equalTo("First Name"))
                .body("session.id_token.representee.family_name", equalTo("Surname"))
                .body("session.id_token.representee.mandates[0].role", equalTo("role"));
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
