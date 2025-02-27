package ee.ria.govsso.session.service.tara;

import ch.qos.logback.classic.Level;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.util.LocaleUtil;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static com.nimbusds.jose.JWSAlgorithm.RS384;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasLength;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class TaraServiceTest extends BaseTest { // TODO: Consider moving these tests under appropriate *Controller tests
    private final TaraService taraService;
    private final TaraConfigurationProperties taraConfigurationProperties;

    @BeforeAll
    static void setUp() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @Test
    void createAuthenticationRequest_WhenCreated_ContainsValidRequestParameters() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", TEST_LOGIN_CHALLENGE);
        ClientID clientID = authenticationRequest.getClientID();

        assertThat(clientID.getValue(), equalTo(taraConfigurationProperties.clientId()));
        assertThat(authenticationRequest.getState(), notNullValue());
        assertThat(authenticationRequest.getNonce(), notNullValue());
        assertThat(authenticationRequest.getState().getValue(), hasLength(43));
        assertThat(authenticationRequest.getNonce().getValue(), hasLength(43));
        assertThat(authenticationRequest.getEndpointURI().toString(), equalTo(TARA_MOCK_URL + "/oidc/authorize"));
        assertThat(authenticationRequest.getRedirectionURI().toString(), equalTo(INPROXY_MOCK_URL + "/login/taracallback"));
        assertThat(authenticationRequest.getCustomParameter("govsso_login_challenge").get(0), equalTo(TEST_LOGIN_CHALLENGE));
        assertThat(authenticationRequest.getACRValues().get(0).toString(), equalTo("high"));
        assertThat(authenticationRequest.getUILocales().get(0).toString(), equalTo(LocaleUtil.DEFAULT_LOCALE.getLanguage()));
        List<String> scopes = authenticationRequest.getScope().toStringList();
        assertThat(authenticationRequest.getResponseType().toString(), equalTo("code"));
        assertThat(scopes, contains("openid", "phone"));
    }

    @Test
    void requestIdToken_WhenInvalidCode_ThrowsIllegalArgumentException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        JWTClaimsSet claimsSet = createClaimSet(authenticationRequest);
        OIDCTokenResponse unsignedTokenResponse = getTokenResponse(claimsSet, false);
        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(unsignedTokenResponse.toJSONObject().toJSONString())));

        IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
                () -> taraService.requestIdToken(""));

        assertThat(illegalArgumentException.getMessage(), equalTo("The value must not be null or empty string"));
    }

    @Test
    void requestIdToken_WhenUnsignedJwtTokenResponse_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        JWTClaimsSet claimsSet = createClaimSet(authenticationRequest);
        OIDCTokenResponse unsignedTokenResponse = getTokenResponse(claimsSet, false);
        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(unsignedTokenResponse.toJSONObject().toJSONString())));

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("Unsigned ID Token"));

        assertMessageWithMarkerIsLoggedOnce(TaraService.class, Level.INFO, "TARA request",
                "http.request.method=POST, url.full=https://tara.localhost:10000/oidc/token");
        assertMessageWithMarkerIsLoggedOnce(TaraService.class, Level.INFO, "TARA response",
                "http.response.status_code=200, http.response.body.content=\"{\\\"access_token\\\":\\\"");
    }

    @Test
    void requestIdToken_WhenTokenEndpointStatus404_ThrowsSsoException() {
        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(404)));

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("ErrorCode:null, Error description:null, Status Code:404"));

        assertMessageWithMarkerIsLoggedOnce(TaraService.class, Level.INFO, "TARA request",
                "http.request.method=POST, url.full=https://tara.localhost:10000/oidc/token");
        assertMessageWithMarkerIsLoggedOnce(TaraService.class, Level.INFO, "TARA response",
                "http.response.status_code=404");
    }

    @Test
    void requestIdToken_WhenTokenEndpointStatus400_ThrowsSsoException() {
        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(400)));

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("ErrorCode:null, Error description:null, Status Code:400"));

        assertMessageWithMarkerIsLoggedOnce(TaraService.class, Level.INFO, "TARA request",
                "http.request.method=POST, url.full=https://tara.localhost:10000/oidc/token");
        assertMessageWithMarkerIsLoggedOnce(TaraService.class, Level.INFO, "TARA response",
                "http.response.status_code=400");
    }

    @Test
    void requestIdToken_WhenTokenEndpointRequestTimeout_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        JWTClaimsSet claimsSet = createClaimSet(authenticationRequest);
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);

        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(signedTokenResponse.toJSONObject().toJSONString())
                        .withFixedDelay(taraConfigurationProperties.connectTimeoutMilliseconds() + 100)));

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("Unable to request ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Read timed out"));
    }

    @Test
    void requestIdToken_WhenMissingTokenType_ThrowsSsoException() {
        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{}")));

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("Unable to request ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Missing JSON object member with key token_type"));
    }

    @Test
    void requestIdToken_WhenInvalidTokenType_ThrowsSsoException() {
        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{ \"token_type\": \"abc123\"}")));

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("Unable to request ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Unsupported token_type: abc123"));
    }

    @Test
    void requestIdToken_WhenMissingAccessToken_ThrowsSsoException() {
        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{ \"token_type\": \"bearer\"}")));

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("Unable to request ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Missing JSON object member with key access_token"));
    }

    @Test
    void requestIdToken_WhenInvalidTokenEndpointResponseBody_ThrowsSsoException() {
        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("abc123")));

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("Unable to request ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Invalid JSON"));
        assertThat(cause.getCause().getMessage(), containsString("Unexpected token abc123 at position"));
    }

    @Test
    void verifyIdToken_WhenAuthenticationRequestNull_ThrowsIllegalArgumentException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        JWTClaimsSet claimsSet = createClaimSet(authenticationRequest);
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT idToken = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        NullPointerException exception = assertThrows(NullPointerException.class, () -> taraService.verifyIdToken(null,
                idToken, TEST_LOGIN_CHALLENGE));

        assertThat(exception.getMessage(), equalTo("nonce is marked non-null but is null"));
    }

    @Test
    void verifyIdToken_WhenIdTokenNull_ThrowsIllegalArgumentException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();

        NullPointerException exception = assertThrows(NullPointerException.class,
                () -> taraService.verifyIdToken(nonce, null, TEST_LOGIN_CHALLENGE));

        assertThat(exception.getMessage(), equalTo("idToken is marked non-null but is null"));
    }

    @Test
    void verifyIdToken_WhenInvalidJWSAlgorithm_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponseWithIncorrectJWSAlgorithm(claimsSet);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Signed JWT rejected: Another algorithm expected, or no matching key(s) found"));
    }

    @Test
    void verifyIdToken_WhenInvalidSignature_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponseWithIncorrectSignature(claimsSet);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Signed JWT rejected: Invalid signature"));
    }

    @Test
    void verifyIdToken_WhenMissingNonce_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("state", state)
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Missing JWT nonce (nonce) claim"));
    }

    @Test
    void verifyIdToken_WhenInvalidNonce_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", "abc123")
                .claim("state", state)
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Unexpected JWT nonce (nonce) claim: abc123"));
    }

    @Test
    void verifyIdToken_WhenInvalidAudience_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience("unknownclient123")
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Unexpected JWT audience: [unknownclient123]"));
    }

    @Test
    void verifyIdToken_WhenMissingAudience_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Missing JWT audience (aud) claim"));
    }

    @Test
    void verifyIdToken_WhenMissingSubject_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .issuer(TARA_MOCK_URL)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Missing JWT subject (sub) claim"));
    }

    @Test
    void verifyIdToken_WhenInvalidIssuer_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer("https://unknownissuer:9877")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Unexpected JWT issuer: https://unknownissuer:9877"));
    }

    @Test
    void verifyIdToken_WhenMissingIssuer_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Missing JWT issuer (iss) claim"));
    }

    @Test
    void verifyIdToken_WhenIssueTimeAheadOfCurrentTime_ThrowsSsoException() {
        Integer maxClockSkew = taraConfigurationProperties.maxClockSkewSeconds();
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew).plusSeconds(1)))
                .expirationTime(Date.from(Instant.now().plusSeconds(maxClockSkew).plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("JWT issue time ahead of current time"));
    }

    @Test
    void verifyIdToken_WhenIssueTimeMissing_ThrowsSsoException() {
        Integer maxClockSkew = taraConfigurationProperties.maxClockSkewSeconds();
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .expirationTime(Date.from(Instant.now().plusSeconds(maxClockSkew).plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Missing JWT issue time (iat) claim"));
    }

    @Test
    void verifyIdToken_WhenIssueTimeAheadOfCurrentTimeWithinAcceptableSkew_TokenValid() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        Integer maxClockSkew = taraConfigurationProperties.maxClockSkewSeconds();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", authenticationRequest.getNonce().getValue())
                .claim("state", authenticationRequest.getState().getValue())
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew)))
                .expirationTime(Date.from(Instant.now().plusSeconds(maxClockSkew).plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        taraService.verifyIdToken(authenticationRequest.getNonce().getValue(), signedJWT, TEST_LOGIN_CHALLENGE);
    }

    @Test
    void verifyIdToken_WhenExpired_ThrowsSsoException() {
        Integer maxClockSkew = taraConfigurationProperties.maxClockSkewSeconds();
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(Date.from(Instant.now().minusSeconds(60)))
                .expirationTime(Date.from(Instant.now().minusSeconds(maxClockSkew)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Expired JWT"));
    }

    @Test
    void verifyIdToken_WhenExpirationTimeMissing_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(Date.from(Instant.now().minusSeconds(60)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Missing JWT expiration (exp) claim"));
    }

    @Test
    void verifyIdToken_WhenGovssoLoginChallengeMissing_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("state", state)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Invalid TARA callback govsso login challenge"));
    }

    @Test
    void verifyIdToken_WhenGovssoLoginChallengeInvalid_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        String nonce = authenticationRequest.getNonce().getValue();
        String state = authenticationRequest.getState().getValue();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("govsso_login_challenge", "invalidLoginChallenge")
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(nonce, signedJWT, TEST_LOGIN_CHALLENGE));

        assertThat(ssoException.getMessage(), equalTo("Invalid TARA callback govsso login challenge"));
    }

    @Test
    void verifyIdToken_WhenExpirationTimeWithinAcceptableSkew_TokenValid() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", "test");
        Integer maxClockSkew = taraConfigurationProperties.maxClockSkewSeconds();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", authenticationRequest.getNonce().getValue())
                .claim("state", authenticationRequest.getState().getValue())
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().minusSeconds(maxClockSkew).plusMillis(50)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        taraService.verifyIdToken(authenticationRequest.getNonce().getValue(), signedJWT, TEST_LOGIN_CHALLENGE);
    }

    private JWTClaimsSet createClaimSet(AuthenticationRequest authenticationRequest) {
        return new JWTClaimsSet.Builder()
                .claim("nonce", authenticationRequest.getNonce().getValue())
                .claim("state", authenticationRequest.getState().getValue())
                .claim("govsso_login_challenge", TEST_LOGIN_CHALLENGE)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
    }

    @SneakyThrows
    private OIDCTokenResponse getTokenResponse(JWTClaimsSet claimsSet, boolean isSigned) {
        return createTokenResponse(claimsSet, isSigned, RS256, TARA_JWK);
    }

    @SneakyThrows
    private OIDCTokenResponse getTokenResponseWithIncorrectJWSAlgorithm(JWTClaimsSet claimsSet) {
        return createTokenResponse(claimsSet, true, RS384, TARA_JWK);
    }

    @SneakyThrows
    private OIDCTokenResponse getTokenResponseWithIncorrectSignature(JWTClaimsSet claimsSet) {
        RSAKey invalidKey = new RSAKeyGenerator(4096)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();

        return createTokenResponse(claimsSet, true, RS256, invalidKey);
    }

    private OIDCTokenResponse createTokenResponse(JWTClaimsSet claimsSet, boolean isSigned, JWSAlgorithm algorithm, RSAKey rsaKey) throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(algorithm).keyID(TARA_JWK.getKeyID()).build(), claimsSet);
        BearerAccessToken accessToken = new BearerAccessToken();
        RefreshToken refreshToken = new RefreshToken();
        OIDCTokens oidcTokens = new OIDCTokens(jwt, accessToken, refreshToken);

        if (isSigned) {
            JWSSigner signer = new RSASSASigner(rsaKey);
            jwt.sign(signer);
        }
        return new OIDCTokenResponse(oidcTokens);
    }
}
