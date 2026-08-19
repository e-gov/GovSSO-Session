package ee.ria.govsso.session.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.ClientRequestLogger;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.time.Clock;

import static com.nimbusds.jose.jwk.source.JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT;
import static ee.ria.govsso.session.logging.ClientRequestLogger.Service.HYDRA;
import static ee.ria.govsso.session.service.helper.ClientScopes.SCOPE_AUTH_HANDOVER;

@Slf4j
@Component
public class AuthHandoverTokenVerifier {

    static final String JWK_SET_PATH = ".well-known/jwks.json";
    private static final JWSAlgorithm EXPECTED_SIGNING_ALGORITHM = JWSAlgorithm.RS256;
    private static final int CONNECT_TIMEOUT_MILLISECONDS = 5000;
    private static final int READ_TIMEOUT_MILLISECONDS = 5000;
    private static final int MAX_CLOCK_SKEW_SECONDS = 0;

    private final ClientRequestLogger requestLogger =
            new ClientRequestLogger(AuthHandoverTokenVerifier.class, HYDRA);
    private final DefaultJWTProcessor<SecurityContext> jwtProcessor;

    @SneakyThrows
    AuthHandoverTokenVerifier(
            SsoConfigurationProperties ssoConfigurationProperties,
            @Qualifier("hydraTrustStore") KeyStore hydraTrustStore,
            Clock clock) {
        URL baseUrl = ssoConfigurationProperties.getBaseUrl();
        URL jwkSetUrl = new URL(baseUrl, JWK_SET_PATH);
        JWKSource<SecurityContext> jwkSource = JWKSourceBuilder
                .create(jwkSetUrl, createResourceRetriever(hydraTrustStore))
                .build();
        AuthHandoverTokenClaimsVerifier claimsVerifier = new AuthHandoverTokenClaimsVerifier(
                baseUrl.toString(), baseUrl.toString(), SCOPE_AUTH_HANDOVER, clock);
        claimsVerifier.setMaxClockSkew(MAX_CLOCK_SKEW_SECONDS);
        jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(EXPECTED_SIGNING_ALGORITHM, jwkSource));
        jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);
    }

    public JWTClaimsSet verify(SignedJWT token) {
        try {
            return jwtProcessor.process(token, null);
        } catch (KeySourceException ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL,
                    "Unable to retrieve JSON web key set for auth handover token verification", ex);
        } catch (BadJOSEException | JOSEException ex) {
            throw new SsoException(ErrorCode.USER_INVALID_OIDC_REQUEST,
                    "Auth handover token verification failed", ex);
        }
    }

    private ResourceRetriever createResourceRetriever(KeyStore trustStore) {
        DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(
                CONNECT_TIMEOUT_MILLISECONDS,
                READ_TIMEOUT_MILLISECONDS,
                DEFAULT_HTTP_SIZE_LIMIT,
                true,
                createSslSocketFactory(trustStore));
        return url -> {
            requestLogger.request(HttpMethod.GET, url.toString()).log();
            try {
                Resource resource = resourceRetriever.retrieveResource(url);
                requestLogger.response(HttpStatus.OK).body(resource.getContent()).log();
                return resource;
            } catch (IOException ex) {
                requestLogger.response(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getMessage()).log();
                throw ex;
            }
        };
    }

    @SneakyThrows
    private SSLSocketFactory createSslSocketFactory(KeyStore trustStore) {
        return SSLContextBuilder.create()
                .setKeyStoreType(trustStore.getType())
                .loadTrustMaterial(trustStore, null)
                .build()
                .getSocketFactory();
    }
}
