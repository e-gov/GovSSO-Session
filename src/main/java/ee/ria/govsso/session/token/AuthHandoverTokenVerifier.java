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
import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.ClientRequestLogger;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URL;
import java.time.Clock;
import java.time.Duration;

import static com.nimbusds.jose.jwk.source.JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT;
import static ee.ria.govsso.session.logging.ClientRequestLogger.Service.HYDRA;
import static ee.ria.govsso.session.service.helper.ClientScopes.SCOPE_AUTH_HANDOVER;

@Slf4j
@Component
public class AuthHandoverTokenVerifier {

    static final String JWT_ACCESS_TOKEN_PATH = "admin/keys/hydra.jwt.access-token";
    private static final String SCOPE_CLAIM = "scope";
    private static final JWSAlgorithm EXPECTED_SIGNING_ALGORITHM = JWSAlgorithm.RS256;
    private static final Duration CONNECT_TIMEOUT = Duration.ofMillis(5000);
    private static final Duration READ_TIMEOUT = Duration.ofMillis(5000);
    private static final Duration MAX_CLOCK_SKEW = Duration.ZERO;

    private final ClientRequestLogger requestLogger =
            new ClientRequestLogger(AuthHandoverTokenVerifier.class, HYDRA);
    private final DefaultJWTProcessor<SecurityContext> jwtProcessor;

    @SneakyThrows
    AuthHandoverTokenVerifier(
            SsoConfigurationProperties ssoConfigurationProperties,
            HydraConfigurationProperties hydraConfigurationProperties,
            @Qualifier("hydraTrustContext") SSLContext hydraTrustContext,
            Clock clock) {
        URL jwkSetUrl = new URL(hydraConfigurationProperties.adminUrl(), JWT_ACCESS_TOKEN_PATH);
        /*
         * JWKSourceBuilder defaults: no JWK set is fetched at startup, nor periodically.
         * The JWK set is fetched on the first validation and cached for 5 minutes.
         * If a token's kid or alg matches no key in the cached set, a refetch is attempted,
         * rate-limited to once per 30 seconds.
         * Thirty seconds before the cache expires, a window opens during which a validation
         * triggers a background refetch; validations keep using the cached set meanwhile.
         * If no validation occurs within that 4:30-5:00 window, no refetch is triggered and
         * the next validation waits for the JWK set to be retrieved.
         * Retries and outage tolerance are off, so a failed fetch fails the validation.
         */
        JWKSource<SecurityContext> jwkSource = JWKSourceBuilder
                .create(jwkSetUrl, createResourceRetriever(hydraTrustContext))
                .build();
        URL baseUrl = ssoConfigurationProperties.getBaseUrl();
        JWTClaimsSet exactMatchClaims = new JWTClaimsSet.Builder()
                .issuer(baseUrl.toString())
                .claim(SCOPE_CLAIM, SCOPE_AUTH_HANDOVER)
                .build();
        AuthHandoverTokenClaimsVerifier claimsVerifier = new AuthHandoverTokenClaimsVerifier(
                baseUrl.toString(), exactMatchClaims, clock);
        claimsVerifier.setMaxClockSkew(Math.toIntExact(MAX_CLOCK_SKEW.toSeconds()));
        jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(EXPECTED_SIGNING_ALGORITHM, jwkSource));
        jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);
    }

    public void verify(SignedJWT token) {
        try {
            jwtProcessor.process(token, null);
        } catch (KeySourceException ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL,
                    "Unable to retrieve JSON web key set for auth handover token verification", ex);
        } catch (BadJOSEException | JOSEException ex) {
            throw new SsoException(ErrorCode.USER_INVALID_OIDC_REQUEST,
                    "Auth handover token verification failed", ex);
        }
    }

    private ResourceRetriever createResourceRetriever(SSLContext hydraTrustContext) {
        DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(
                Math.toIntExact(CONNECT_TIMEOUT.toMillis()),
                Math.toIntExact(READ_TIMEOUT.toMillis()),
                DEFAULT_HTTP_SIZE_LIMIT,
                true,
                hydraTrustContext.getSocketFactory());
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
}
