package ee.ria.govsso.session.service.tara;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.ClientRequestLogger;
import ee.ria.govsso.session.util.RequestUtil;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Locale;

import static com.nimbusds.jose.jwk.source.RemoteJWKSet.DEFAULT_HTTP_CONNECT_TIMEOUT;
import static com.nimbusds.jose.jwk.source.RemoteJWKSet.DEFAULT_HTTP_READ_TIMEOUT;
import static com.nimbusds.oauth2.sdk.ResponseType.Value.CODE;
import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.OPENID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TaraService {

    private final ClientRequestLogger requestLogger = new ClientRequestLogger(this.getClass(), "TARA");
    private final TaraConfigurationProperties taraConfigurationProperties;
    private final SsoConfigurationProperties ssoConfigurationProperties;
    private final TaraMetadataService taraMetadataService;
    @Qualifier("taraTrustContext")
    private final SSLContext trustContext;

    @SneakyThrows
    public AuthenticationRequest createAuthenticationRequest(String acrValue) {
        ClientID clientID = new ClientID(taraConfigurationProperties.clientId());
        URI callback = ssoConfigurationProperties.getCallbackUri();
        State state = new State();
        Nonce nonce = new Nonce();
        ResponseType responseType = new ResponseType(CODE);
        Scope scope = new Scope(OPENID);

        return new AuthenticationRequest.Builder(responseType, scope, clientID, callback)
                .endpointURI(taraMetadataService.getMetadata().getAuthorizationEndpointURI())
                .state(state)
                .nonce(nonce)
                .acrValues(List.of(new ACR(acrValue)))
                .uiLocales(getUiLocales())
                .build();
    }

    public SignedJWT requestIdToken(String code) {
        try {
            TokenRequest tokenRequest = createTokenRequest(code);
            HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
            httpRequest.setConnectTimeout(DEFAULT_HTTP_CONNECT_TIMEOUT); // TODO: Configurable
            httpRequest.setReadTimeout(DEFAULT_HTTP_READ_TIMEOUT); // TODO: Configurable
            httpRequest.setSSLSocketFactory(trustContext.getSocketFactory());

            requestLogger.logRequest(httpRequest.getURL().toString(), httpRequest.getMethod().name());
            HTTPResponse response = httpRequest.send();
            requestLogger.logResponse(response.getStatusCode(), response.getContent());

            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(response);
            if (!tokenResponse.indicatesSuccess()) {
                ErrorObject errorObject = tokenResponse.toErrorResponse().getErrorObject();
                String errorMessage = "ErrorCode:" + errorObject.getCode() +
                        ", Error description:" + errorObject.getDescription() +
                        ", Status Code:" + errorObject.getHTTPStatusCode();

                if (errorObject.getHTTPStatusCode() == HttpStatus.BAD_REQUEST.value())
                    throw new SsoException(ErrorCode.USER_INPUT_OR_EXPIRED, errorMessage);
                else {
                    throw new SsoException(ErrorCode.TECHNICAL_TARA_UNAVAILABLE, errorMessage);
                }
            }

            OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

            JWT idToken = successResponse.getOIDCTokens().getIDToken();
            if (!(idToken instanceof SignedJWT)) {
                throw new SsoException("Unsigned ID Token");
            }
            return (SignedJWT) idToken;
        } catch (IOException | ParseException ex) {
            throw new SsoException("Unable to request ID Token", ex);
        }
    }

    public void verifyIdToken(@NonNull String nonce, @NonNull SignedJWT idToken) {
        try {
            IDTokenValidator verifier = taraMetadataService.getIDTokenValidator();
            verifier.validate(idToken, Nonce.parse(nonce));
        } catch (BadJOSEException ex) {
            throw new SsoException("Unable to validate ID Token", ex);
        } catch (JOSEException ex) {
            throw new SsoException("Unable to parse ID Token", ex);
        }
    }

    private List<LangTag> getUiLocales() throws LangTagException {
        List<LangTag> uiLocales = null;
        Locale locale = RequestUtil.getLocale();
        if (locale != null) {
            uiLocales = List.of(new LangTag(locale.getLanguage()));
        }
        return uiLocales;
    }

    private TokenRequest createTokenRequest(String code) {
        AuthorizationCode authorizationCode = new AuthorizationCode(code);
        URI callback = ssoConfigurationProperties.getCallbackUri();
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authorizationCode, callback);
        ClientID clientID = new ClientID(taraConfigurationProperties.clientId());
        Secret clientSecret = new Secret(taraConfigurationProperties.clientSecret());
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
        OIDCProviderMetadata metadata = taraMetadataService.getMetadata();
        URI tokenEndpoint = metadata.getTokenEndpointURI();
        return new TokenRequest(tokenEndpoint, clientAuth, codeGrant);
    }
}
