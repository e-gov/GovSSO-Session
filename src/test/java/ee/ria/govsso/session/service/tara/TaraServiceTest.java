package ee.ria.govsso.session.service.tara;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
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
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static com.nimbusds.jose.jwk.source.RemoteJWKSet.DEFAULT_HTTP_CONNECT_TIMEOUT;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasLength;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertThrows;


@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class TaraServiceTest extends BaseTest { // TODO: Consider moving these tests under appropriate *Controller tests
    private final TaraService taraService;
    private final TaraMetadataService taraMetadataService;
    private final TaraConfigurationProperties taraConfigurationProperties;

    @BeforeEach
    void thisShouldNotBeNeededFixMe() { // FIXME:
        setUpTaraMetadataMocks();
        taraMetadataService.updateMetadata();
    }

    @Test
    void createAuthenticationRequest_WhenCreated_ContainsValidRequestParameters() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        ClientID clientID = authenticationRequest.getClientID();

        assertThat(clientID.getValue(), equalTo(taraConfigurationProperties.getClientId()));
        assertThat(authenticationRequest.getState(), notNullValue());
        assertThat(authenticationRequest.getNonce(), notNullValue());
        assertThat(authenticationRequest.getState().getValue(), hasLength(43));
        assertThat(authenticationRequest.getNonce().getValue(), hasLength(43));
        assertThat(authenticationRequest.getEndpointURI().toString(), equalTo("https://localhost:9877/oidc/authorize"));
        assertThat(authenticationRequest.getRedirectionURI().toString(), equalTo("http://localhost:9877/auth/taracallback"));
        List<String> scopes = authenticationRequest.getScope().toStringList();
        assertThat(authenticationRequest.getResponseType().toString(), equalTo("code"));
        assertThat(scopes, contains("openid"));
    }

    @Test
    void requestIdToken_WhenInvalidCode_ThrowsIllegalArgumentException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        JWTClaimsSet claimsSet = createClaimSet(authenticationRequest);
        OIDCTokenResponse unsignedTokenResponse = getTokenResponse(claimsSet, false);
        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
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
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        JWTClaimsSet claimsSet = createClaimSet(authenticationRequest);
        OIDCTokenResponse unsignedTokenResponse = getTokenResponse(claimsSet, false);
        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(unsignedTokenResponse.toJSONObject().toJSONString())));

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("Unsigned ID Token"));
    }

    @Test
    void requestIdToken_WhenTokenEndpointStatus404_ThrowsSsoException() {
        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(404)));

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("ErrorCode:null, Error description:null, Status Code:404"));
    }

    @Test
    void requestIdToken_WhenTokenEndpointStatus400_ThrowsSsoException() {
        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(400)));

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("ErrorCode:null, Error description:null, Status Code:400"));
    }

    @Test
    void requestIdToken_WhenTokenEndpointRequestTimeout_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        JWTClaimsSet claimsSet = createClaimSet(authenticationRequest);
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(signedTokenResponse.toJSONObject().toJSONString())
                        .withFixedDelay(DEFAULT_HTTP_CONNECT_TIMEOUT + 100))); // TODO: Configurable

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("Unable to request ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Read timed out"));
    }

    @Test
    void requestIdToken_WhenMissingTokenType_ThrowsSsoException() {
        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
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
        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{ \"token_type\": \"abc123\"}")));

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("Unable to request ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Token type must be Bearer"));
    }

    @Test
    void requestIdToken_WhenMissingAccessToken_ThrowsSsoException() {
        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
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
        wireMockServer.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("abc123")));

        SsoException ssoException = assertThrows(SsoException.class, () -> taraService.requestIdToken("code"));

        assertThat(ssoException.getMessage(), equalTo("Unable to request ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), startsWith("Invalid JSON: Unexpected token abc123 at position"));
    }

    @Test
    void verifyIdToken_WhenAuthenticationRequestNull_ThrowsIllegalArgumentException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        JWTClaimsSet claimsSet = createClaimSet(authenticationRequest);
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);

        NullPointerException exception = assertThrows(NullPointerException.class, () -> taraService.verifyIdToken(null,
                (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken()));

        assertThat(exception.getMessage(), equalTo("nonce is marked non-null but is null"));
    }

    @Test
    void verifyIdToken_WhenIdTokenNull_ThrowsIllegalArgumentException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();

        NullPointerException exception = assertThrows(NullPointerException.class,
                () -> taraService.verifyIdToken(authenticationRequest.getNonce().getValue(), null));

        assertThat(exception.getMessage(), equalTo("idToken is marked non-null but is null"));
    }

    @Test
    void verifyIdToken_WhenMissingNonce_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("state", authenticationRequest.getState().getValue())
                .audience(taraConfigurationProperties.getClientId())
                .subject("test")
                .issuer("https://localhost:9877")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(authenticationRequest.getNonce().getValue(), signedJWT));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Missing JWT nonce (nonce) claim"));
    }

    @Test
    void verifyIdToken_WhenInvalidAudience_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", authenticationRequest.getNonce().getValue())
                .claim("state", authenticationRequest.getState().getValue())
                .audience("unknownclient123")
                .subject("test")
                .issuer("https://localhost:9877")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(authenticationRequest.getNonce().getValue(), signedJWT));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Unexpected JWT audience: [unknownclient123]"));
    }

    @Test
    void verifyIdToken_WhenInvalidIssuer_ThrowsSsoException() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", authenticationRequest.getNonce().getValue())
                .claim("state", authenticationRequest.getState().getValue())
                .audience(taraConfigurationProperties.getClientId())
                .subject("test")
                .issuer("https://unknownissuer:9877")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(authenticationRequest.getNonce().getValue(), signedJWT));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Unexpected JWT issuer: https://unknownissuer:9877"));
    }

    @Test
    void verifyIdToken_WhenIssueTimeAheadOfCurrentTime_ThrowsSsoException() {
        Integer maxClockSkew = taraConfigurationProperties.getMaxClockSkewSeconds();
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", authenticationRequest.getNonce().getValue())
                .claim("state", authenticationRequest.getState().getValue())
                .audience(taraConfigurationProperties.getClientId())
                .subject("test")
                .issuer("https://localhost:9877")
                .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew).plusSeconds(1)))
                .expirationTime(Date.from(Instant.now().plusSeconds(maxClockSkew).plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(authenticationRequest.getNonce().getValue(), signedJWT));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("JWT issue time ahead of current time"));
    }

    @Test
    void verifyIdToken_WhenIssueTimeAheadOfCurrentTimeWithinAcceptableSkew_TokenValid() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        Integer maxClockSkew = taraConfigurationProperties.getMaxClockSkewSeconds();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", authenticationRequest.getNonce().getValue())
                .claim("state", authenticationRequest.getState().getValue())
                .audience(taraConfigurationProperties.getClientId())
                .subject("test")
                .issuer("https://localhost:9877")
                .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew)))
                .expirationTime(Date.from(Instant.now().plusSeconds(maxClockSkew).plusSeconds(10)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        taraService.verifyIdToken(authenticationRequest.getNonce().getValue(), signedJWT);
    }

    @Test
    void verifyIdToken_WhenExpired_ThrowsSsoException() {
        Integer maxClockSkew = taraConfigurationProperties.getMaxClockSkewSeconds();
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", authenticationRequest.getNonce().getValue())
                .claim("state", authenticationRequest.getState().getValue())
                .audience(taraConfigurationProperties.getClientId())
                .subject("test")
                .issuer("https://localhost:9877")
                .issueTime(Date.from(Instant.now().minusSeconds(60)))
                .expirationTime(Date.from(Instant.now().minusSeconds(maxClockSkew)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        SsoException ssoException = assertThrows(SsoException.class,
                () -> taraService.verifyIdToken(authenticationRequest.getNonce().getValue(), signedJWT));

        assertThat(ssoException.getMessage(), equalTo("Unable to validate ID Token"));
        Throwable cause = ssoException.getCause();
        assertThat(cause.getMessage(), equalTo("Expired JWT"));
    }

    @Test
    void verifyIdToken_WhenExpirationTimeWithinAcceptableSkew_TokenValid() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        Integer maxClockSkew = taraConfigurationProperties.getMaxClockSkewSeconds();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", authenticationRequest.getNonce().getValue())
                .claim("state", authenticationRequest.getState().getValue())
                .audience(taraConfigurationProperties.getClientId())
                .subject("test")
                .issuer("https://localhost:9877")
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().minusSeconds(maxClockSkew).plusMillis(50)))
                .build();
        OIDCTokenResponse signedTokenResponse = getTokenResponse(claimsSet, true);
        SignedJWT signedJWT = (SignedJWT) signedTokenResponse.getOIDCTokens().getIDToken();

        taraService.verifyIdToken(authenticationRequest.getNonce().getValue(), signedJWT);
    }

    private JWTClaimsSet createClaimSet(AuthenticationRequest authenticationRequest) {
        return new JWTClaimsSet.Builder()
                .claim("nonce", authenticationRequest.getNonce().getValue())
                .claim("state", authenticationRequest.getState().getValue())
                .audience(taraConfigurationProperties.getClientId())
                .subject("test")
                .issuer("https://localhost:9877")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();
    }

    @SneakyThrows
    private OIDCTokenResponse getTokenResponse(JWTClaimsSet claimsSet, boolean isSigned) {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(RS256).keyID(taraJWK.getKeyID()).build(), claimsSet);
        BearerAccessToken accessToken = new BearerAccessToken();
        RefreshToken refreshToken = new RefreshToken();
        OIDCTokens oidcTokens = new OIDCTokens(jwt, accessToken, refreshToken);

        if (isSigned) {
            JWSSigner signer = new RSASSASigner(taraJWK);
            jwt.sign(signer);
        }
        return new OIDCTokenResponse(oidcTokens);
    }
}
