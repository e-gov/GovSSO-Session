package ee.ria.govsso.session.controller;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import ee.ria.govsso.session.service.tara.TaraService;
import ee.ria.govsso.session.session.SsoSession;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.MapSession;
import org.springframework.session.SessionRepository;

import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static ee.ria.govsso.session.controller.AuthCallbackController.CALLBACK_REQUEST_MAPPING;
import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;
import static io.restassured.RestAssured.given;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class AuthCallbackControllerTest extends BaseTest {

    private final TaraConfigurationProperties taraConfigurationProperties;
    private final SessionRepository<MapSession> sessionRepository;
    private final TaraService taraService;

    @Test
    void authCallback_Ok() {
        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);
        OIDCTokenResponse tokenResponse = getOidcTokenResponse(ssoSession);

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_accept_login_response.json")));

        given()
                .param("code", "testcode")
                .param("state", ssoSession.getTaraAuthenticationRequestState())
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/login/test"));
    }

    @Test
    void authCallback_TaraRespondsWithError() {

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_idToken_response.json")));

        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        given()
                .param("code", "testcode")
                .param("state", ssoSession.getTaraAuthenticationRequestState())
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

        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        given()
                .param("code", "testcode")
                .param("state", ssoSession.getTaraAuthenticationRequestState())
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500);
    }

    private SsoSession createSsoSession() {
        SsoSession.LoginRequestInfo loginRequest = new SsoSession.LoginRequestInfo();
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        SsoSession.Client client = new SsoSession.Client();
        client.setRedirectUris(new String[]{"some/test/url"});
        loginRequest.setClient(client);
        return new SsoSession(loginRequest, authenticationRequest.getState().getValue(), authenticationRequest.getNonce().getValue());
    }

    private String createSession(SsoSession ssoSession) {
        MapSession session = sessionRepository.createSession();
        session.setAttribute(SSO_SESSION, ssoSession);
        sessionRepository.save(session);
        return Base64.getEncoder().withoutPadding().encodeToString(session.getId().getBytes());
    }

    @SneakyThrows
    private OIDCTokenResponse getOidcTokenResponse(SsoSession ssoSession) {
        JWSSigner signer = new RSASSASigner(taraJWK);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", ssoSession.getTaraAuthenticationRequestNonce())
                .claim("state", ssoSession.getTaraAuthenticationRequestState())
                .audience(taraConfigurationProperties.getClientId())
                .subject("test")
                .issuer("https://localhost:9877")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(RS256).keyID(taraJWK.getKeyID()).build(), claimsSet);
        jwt.sign(signer);

        BearerAccessToken accessToken = new BearerAccessToken();
        OIDCTokens oidcTokens = new OIDCTokens(jwt, accessToken, null);
        return new OIDCTokenResponse(oidcTokens);
    }
}
