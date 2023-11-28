package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.controller.RefreshTokenHookController.TOKEN_REFRESH_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

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
                .body("session.consent_remember_for", equalTo(900));
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
                .body("session.consent_remember_for", equalTo(900));
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
