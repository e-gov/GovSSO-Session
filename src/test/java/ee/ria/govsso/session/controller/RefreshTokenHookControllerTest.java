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

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class RefreshTokenHookControllerTest extends BaseTest {

    @Test
    void tokenRefresh_WhenHydraRespondsWith404_ThrowsTechnicalGeneralError() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest();

        given()
                .request().body(hookRequest)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .when()
                .post(TOKEN_REFRESH_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 404 Not Found from GET https://hydra.localhost:9000/oauth2/auth/sessions/consent?subject");
    }

    @Test
    void tokenRefresh_WhenConsentsAreMissing_ThrowsTechnicalGeneralError() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest();
        hookRequest.setSubject("testSubject");

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=testSubject&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
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
    void tokenRefresh_ok() {
        RefreshTokenHookRequest hookRequest = createRefreshTokenHookRequest();
        hookRequest.setSubject("testSubject");

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=testSubject&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
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
                .statusCode(200);
    }

    private RefreshTokenHookRequest createRefreshTokenHookRequest() {
        RefreshTokenHookRequest hookRequest = new RefreshTokenHookRequest();
        RefreshTokenHookRequest.Session session = new RefreshTokenHookRequest.Session();
        RefreshTokenHookRequest.IdToken idToken = new RefreshTokenHookRequest.IdToken();
        RefreshTokenHookRequest.IdTokenClaims idTokenClaims = new RefreshTokenHookRequest.IdTokenClaims();
        RefreshTokenHookRequest.Ext ext = new RefreshTokenHookRequest.Ext();
        ext.setSid("e56cbaf9-81e9-4473-a733-261e8dd38e95");
        idTokenClaims.setExt(ext);

        idToken.setIdTokenClaims(idTokenClaims);
        session.setIdToken(idToken);
        hookRequest.setSession(session);
        hookRequest.setGrantedScopes(List.of("openId", "phone"));
        hookRequest.setClientId("client-a");
        return hookRequest;
    }
}
