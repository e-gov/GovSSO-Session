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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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
import static org.hamcrest.Matchers.equalTo;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class AuthCallbackControllerTest extends BaseTest {

    private static final String TEST_CODE = "_wBCdwHmgifrnus0frBW43BHK74ZR4UDwGsPSX-TwtY.Cqk0T6OtkYZppp_aLHXz_00gMnhiCK6HSZftPfs7BLg";
    private final TaraConfigurationProperties taraConfigurationProperties;
    private final SessionRepository<MapSession> sessionRepository;
    private final TaraService taraService;

    @Test
    void authCallback_WhenTokenRequestAndAcceptRequestAreSuccessful_Redirects() {
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
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .param("code", TEST_CODE)
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
    void authCallback_WhenCodeParameterIsMissing_ThrowsUserInputError() {

        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        given()
                .param("state", ssoSession.getTaraAuthenticationRequestState())
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenCodeParameterIsDuplicate_ThrowsUserInputError() {

        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        given()
                .param("code", TEST_CODE)
                .param("code", TEST_CODE)
                .param("state", ssoSession.getTaraAuthenticationRequestState())
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"",
            "_wBCd",
            "_wBCdwHmgifrnus0frBW43BHK74ZR4UDwGsPSX+TwtY.Cqk0T6OtkYZppp_aLHXz_00gMnhiCK6HSZftPfs7BLg",
            "_wBCdwHmgifrnus0frBW43BHK74ZR4UDwGsPSX-TwtY.Cqk0T6OtkYZppp_aLHXz_00gMnhiCK6HSZftPfs7BLgg"})
    void authCallback_WhenCodeParameterIsInvalid_ThrowsUserInputError(String codeParameter) {

        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        given()
                .param("code", codeParameter)
                .param("state", ssoSession.getTaraAuthenticationRequestState())
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenStateParameterIsMissing_ThrowsUserInputError() {

        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        given()
                .param("code", TEST_CODE)
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenStateParameterIsDuplicate_ThrowsUserInputError() {

        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        given()
                .param("code", TEST_CODE)
                .param("state", ssoSession.getTaraAuthenticationRequestState())
                .param("state", ssoSession.getTaraAuthenticationRequestState())
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"",
            "727cWytFrnR5Qnd3.WJ2ceQVFNQIjEI05TNguUzjE9E",
            "727cWytFrnR5Qnd3_WJ2ceQVFNQIjEI05TNguUzjE9EE",
            "727cWytFrnR5Qnd3_WJ2ceQVFNQIjEI05TNguUzjE9"})
    void authCallback_WhenStateParameterIsInvalid_ThrowsUserInputError(String stateParameter) {

        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        given()
                .param("code", TEST_CODE)
                .param("state", stateParameter)
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenRequestIdTokenRespondsWith500_ThrowsTechnicalGeneralError() {

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_tara_oidc_token.json")));

        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        given()
                .param("code", TEST_CODE)
                .param("state", ssoSession.getTaraAuthenticationRequestState())
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void authCallback_WhenRequestIdTokenRespondsWith400_ThrowsUserInputOrExpiredError() {

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_tara_oidc_token.json")));

        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        given()
                .param("code", TEST_CODE)
                .param("state", ssoSession.getTaraAuthenticationRequestState())
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT_OR_EXPIRED"));
    }

    @Test
    void authCallback_WhenAcceptLoginRespondsWith500_ThrowsTechnicalGeneralError() {

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_tara_oidc_token.json")));

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge"))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        SsoSession ssoSession = createSsoSession();
        String sessionId = createSession(ssoSession);

        given()
                .param("code", TEST_CODE)
                .param("state", ssoSession.getTaraAuthenticationRequestState())
                .when()
                .sessionId("SESSION", sessionId)
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));
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
