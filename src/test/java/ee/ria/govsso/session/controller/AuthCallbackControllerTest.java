package ee.ria.govsso.session.controller;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import ee.ria.govsso.session.service.tara.TaraService;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieSigner;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.util.Date;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static ee.ria.govsso.session.controller.AuthCallbackController.CALLBACK_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static java.util.Collections.emptyMap;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.HttpHeaders.ORIGIN;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class AuthCallbackControllerTest extends BaseTest {

    private static final String TEST_LOGIN_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";
    private static final String TEST_CODE = "_wBCdwHmgifrnus0frBW43BHK74ZR4UDwGsPSX-TwtY.Cqk0T6OtkYZppp_aLHXz_00gMnhiCK6HSZftPfs7BLg";
    private static final String TEST_STATE = "VuF_ylfAWHflipdR2d6xKGLh6VB_7UrNetD3lXfOc0g";
    private final TaraConfigurationProperties taraConfigurationProperties;
    private final TaraService taraService;
    private final SsoCookieSigner ssoCookieSigner;

    @Test
    void authCallback_WhenTokenRequestAndAcceptRequestAreSuccessful_Redirects() {
        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "high");

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/login/test"));
    }

    @Test
    void authCallback_WhenTokenRequestWithSubstantialAcrAndIdTokenWithLowAcr_ThrowsUserInputError() {
        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "low");

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_substantial_acr.json")));

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenTokenLoginRequestResponseAcrIsEmpty_Redirects() {
        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "high");

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_empty_acr.json")));

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/login/test"));
    }

    @Test
    void authCallback_WhenTokenRequestResponseAcrIsLow_ThrowsUserInputError() {
        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "low");

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_empty_acr.json")));

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenCodeParameterIsMissing_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenCodeParameterIsDuplicate_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
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

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", codeParameter)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenStateParameterIsMissing_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenStateParameterIsDuplicate_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenStateParameterNotValidatingAgainstSsoCookie_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("state", new State().getValue())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenSsoCookieMissing_ThrowsUserInputError() {

        given()
                .param("code", TEST_CODE)
                .param("state", TEST_STATE)
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_COOKIE_MISSING"));
    }

    @Test
    void authCallback_WhenSsoCookieTaraStateValueIsNull_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie().withTaraAuthenticationRequestState(null);

        given()
                .param("code", TEST_CODE)
                .param("state", TEST_STATE)
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenSsoCookieTaraStateValueIsBlank_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie();
        ssoCookie.withTaraAuthenticationRequestState(" ");

        given()
                .param("code", TEST_CODE)
                .param("state", TEST_STATE)
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenSsoCookieTaraNonceValueIsNull_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie().withTaraAuthenticationRequestNonce(null);

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenSsoCookieTaraNonceValueIsBlank_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie().withTaraAuthenticationRequestNonce(" ");

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
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

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("state", stateParameter)
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void authCallback_WhenRequestIdTokenRespondsWith500_ThrowsTechnicalGeneralError() {

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_tara_oidc_token.json")));

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_TARA_UNAVAILABLE"));
    }

    @Test
    void authCallback_WhenRequestIdTokenRespondsWith400_ThrowsUserInputOrExpiredError() {

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_tara_oidc_token.json")));

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT_OR_EXPIRED"));
    }

    @Test
    void authCallback_WhenAcceptLoginRespondsWith500_ThrowsTechnicalGeneralError() {

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

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

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void authCallback_WhenOriginHeaderIsSet_NoCorsResponseHeadersAreSet() {

        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "high");

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .header(ORIGIN, "https://clienta.localhost:11443")
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .headers(emptyMap())
                .header("Location", Matchers.containsString("auth/login/test"));
    }

    private SsoCookie createSsoCookie() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high");
        return SsoCookie.builder()
                .loginChallenge(TEST_LOGIN_CHALLENGE)
                .taraAuthenticationRequestState(authenticationRequest.getState().getValue())
                .taraAuthenticationRequestNonce(authenticationRequest.getNonce().getValue())
                .build();
    }

    @SneakyThrows
    private OIDCTokenResponse getTaraOidcTokenResponse(SsoCookie ssoCookie, String acr) {
        JWSSigner signer = new RSASSASigner(taraJWK);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", ssoCookie.getTaraAuthenticationRequestNonce())
                .claim("state", ssoCookie.getTaraAuthenticationRequestState())
                .claim("acr", acr)
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
