package ee.ria.govsso.session.service.tara;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.WellKnownPathComposeStrategy;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.ClientRequestLogger;
import ee.ria.govsso.session.util.ExceptionUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URL;

import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static com.nimbusds.jose.jwk.source.RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT;
import static com.nimbusds.oauth2.sdk.GrantType.AUTHORIZATION_CODE;
import static com.nimbusds.oauth2.sdk.ResponseType.CODE;
import static com.nimbusds.oauth2.sdk.WellKnownPathComposeStrategy.INFIX;
import static com.nimbusds.oauth2.sdk.WellKnownPathComposeStrategy.POSTFIX;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
import static com.nimbusds.oauth2.sdk.util.CollectionUtils.contains;
import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.OPENID;
import static com.nimbusds.openid.connect.sdk.SubjectType.PUBLIC;
import static com.nimbusds.openid.connect.sdk.claims.ClaimType.NORMAL;
import static ee.ria.govsso.session.logging.ClientRequestLogger.Service.TARA;

@Slf4j
@Service
@RequiredArgsConstructor
public class TaraMetadataService {

    private final ClientRequestLogger requestLogger = new ClientRequestLogger(this.getClass(), TARA);
    private final TaraConfigurationProperties taraConfigurationProperties;
    @Qualifier("taraTrustContext")
    private final SSLContext trustContext;
    private volatile Tuple2<OIDCProviderMetadata, IDTokenValidator> providerMetadata;

    public OIDCProviderMetadata getMetadata() {
        if (providerMetadata == null) {
            throw new SsoException(ErrorCode.TECHNICAL_TARA_UNAVAILABLE, "TARA metadata not available");
        }
        return providerMetadata.getT1();
    }

    public IDTokenValidator getIDTokenValidator() {
        if (providerMetadata == null) {
            throw new SsoException(ErrorCode.TECHNICAL_TARA_UNAVAILABLE, "TARA metadata not available");
        }
        return providerMetadata.getT2();
    }

    @Scheduled(fixedRateString = "${govsso.tara.metadata-interval:PT24H}")
    @Retryable(value = SsoException.class,
            maxAttemptsExpression = "${govsso.tara.metadata-max-attempts:1440}",
            backoff = @Backoff(delayExpression = "${govsso.tara.metadata-backoff-delay-milliseconds:1000}",
                    maxDelayExpression = "${govsso.tara.metadata-backoff-max-delay-milliseconds:60000}",
                    multiplierExpression = "${govsso.tara.metadata-backoff-multiplier:1.1}"))
    void updateMetadata() {
        try {
            OIDCProviderMetadata metadata = requestMetadata();
            JWKSet jwkSet = requestJWKSet(metadata);
            IDTokenValidator idTokenValidator = createIdTokenValidator(metadata, jwkSet);
            providerMetadata = Tuples.of(metadata, idTokenValidator);
        } catch (Exception ex) {
            providerMetadata = null;
            log.error("Unable to update TARA metadata: {}", ExceptionUtil.getCauseMessages(ex), ex);
            throw new SsoException("Unable to update TARA metadata", ex);
        }
    }

    OIDCProviderMetadata requestMetadata() throws IOException, ParseException {
        String issuerUrl = taraConfigurationProperties.issuerUrl().toString();
        Issuer issuer = new Issuer(issuerUrl);
        WellKnownPathComposeStrategy strategy = issuerUrl.endsWith("/") ? POSTFIX : INFIX;
        OIDCProviderConfigurationRequest request = new OIDCProviderConfigurationRequest(issuer, strategy);
        HTTPRequest httpRequest = request.toHTTPRequest();
        httpRequest.setConnectTimeout(taraConfigurationProperties.connectTimeoutMilliseconds());
        httpRequest.setReadTimeout(taraConfigurationProperties.readTimeoutMilliseconds());
        httpRequest.setSSLSocketFactory(trustContext.getSocketFactory());

        requestLogger.logRequest(request.getEndpointURI().toString(), httpRequest.getMethod().toString());
        HTTPResponse httpResponse = httpRequest.send();
        requestLogger.logResponse(httpResponse.getStatusCode(), httpResponse.getContent());

        JSONObject contentAsJSONObject = httpResponse.getContentAsJSONObject();
        OIDCProviderMetadata metadata = OIDCProviderMetadata.parse(contentAsJSONObject);

        validateMetadata(issuerUrl, metadata);

        return metadata;
    }

    private void validateMetadata(String issuerUrl, OIDCProviderMetadata metadata) throws ParseException {
        String metadataIssuer = metadata.getIssuer().getValue();

        if (!issuerUrl.equals(metadataIssuer))
            throw new ParseException(String.format("Expected OIDC Issuer '%s' does not match published issuer '%s'", issuerUrl, metadataIssuer));
        if (metadata.getAuthorizationEndpointURI() == null || metadata.getAuthorizationEndpointURI().toString().isBlank())
            throw new ParseException("The public authorization endpoint URI must not be null");
        if (metadata.getTokenEndpointURI() == null || metadata.getTokenEndpointURI().toString().isBlank())
            throw new ParseException("The public token endpoint URI must not be null");
        if (!contains(metadata.getSubjectTypes(), PUBLIC) || metadata.getSubjectTypes().size() != 1)
            throw new ParseException(String.format("Metadata subject types must contain only '%s'", PUBLIC));
        if (!contains(metadata.getResponseTypes(), CODE) || metadata.getResponseTypes().size() != 1)
            throw new ParseException(String.format("Metadata response types can not be null and must contain only '%s'", CODE));
        if (!contains(metadata.getClaims(), "sub"))
            throw new ParseException("Metadata claims can not be null and must contain: 'sub'");
        if (!contains(metadata.getGrantTypes(), AUTHORIZATION_CODE))
            throw new ParseException(String.format("Metadata grant types can not be null and must contain: '%s'", AUTHORIZATION_CODE));
        if (!contains(metadata.getIDTokenJWSAlgs(), RS256) || metadata.getIDTokenJWSAlgs().size() != 1)
            throw new ParseException(String.format("Metadata ID token JWS algorithms can not be null and must contain only '%s'", RS256));
        if (!contains(metadata.getClaimTypes(), NORMAL) || metadata.getClaimTypes().size() != 1)
            throw new ParseException(String.format("Metadata claim types can not be null and must contain only '%s'", NORMAL));
        if (!contains(metadata.getTokenEndpointAuthMethods(), CLIENT_SECRET_BASIC))
            throw new ParseException(String.format("Metadata token endpoint auth methods can not be null and must contain '%s'", CLIENT_SECRET_BASIC));
        if (!contains(metadata.getScopes(), OPENID))
            throw new ParseException("Metadata scopes can not be null and must contain 'openid'");
    }

    JWKSet requestJWKSet(OIDCProviderMetadata metadata) throws IOException, java.text.ParseException {
        DefaultResourceRetriever rr = new DefaultResourceRetriever(
                taraConfigurationProperties.connectTimeoutMilliseconds(),
                taraConfigurationProperties.readTimeoutMilliseconds(),
                DEFAULT_HTTP_SIZE_LIMIT,
                true,
                trustContext.getSocketFactory());
        URL jwkSetUri = metadata.getJWKSetURI().toURL();

        requestLogger.logRequest(jwkSetUri.toString(), HttpMethod.GET.name());
        Resource resource;
        try {
            resource = rr.retrieveResource(jwkSetUri);
            requestLogger.logResponse(HttpStatus.OK.value(), resource.getContent());
        } catch (IOException e) {
            requestLogger.logResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), e.getMessage());
            throw e;
        }

        return JWKSet.parse(resource.getContent());
    }

    IDTokenValidator createIdTokenValidator(OIDCProviderMetadata metadata, JWKSet jwkSet) {
        Issuer issuer = metadata.getIssuer();
        ClientID clientID = new ClientID(taraConfigurationProperties.clientId());
        JWSAlgorithm jwsAlg = RS256;
        IDTokenValidator idTokenValidator = new IDTokenValidator(issuer, clientID, jwsAlg, jwkSet);
        idTokenValidator.setMaxClockSkew(taraConfigurationProperties.maxClockSkewSeconds());
        return idTokenValidator;
    }
}
