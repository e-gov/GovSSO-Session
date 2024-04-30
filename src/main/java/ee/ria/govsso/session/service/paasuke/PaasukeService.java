package ee.ria.govsso.session.service.paasuke;

import ee.ria.govsso.session.configuration.properties.PaasukeConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.XRoadConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.HttpTimeoutRuntimeException;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.ClientRequestLogger;
import ee.ria.govsso.session.xroad.XRoadHeaders;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.hc.core5.net.WWWFormCodec;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;

import static ee.ria.govsso.session.logging.ClientRequestLogger.Service.PAASUKE;
import static java.nio.charset.StandardCharsets.UTF_8;

@Service
@RequiredArgsConstructor
public class PaasukeService {

    private final ClientRequestLogger requestLogger = new ClientRequestLogger(PaasukeService.class, PAASUKE);

    @Qualifier("paasukeWebClient")
    private final WebClient webclient;
    private final PaasukeConfigurationProperties paasukeConfigurationProperties;
    private final XRoadConfigurationProperties xRoadConfigurationProperties;

    public MandateTriplet fetchMandates(@NonNull String representee, @NonNull String delegate, @NonNull String queryParams) {
        URI uri;
        try {
            uri = new URIBuilder(paasukeConfigurationProperties.hostUrl().toURI())
                    .appendPathSegments("representees", representee, "delegates", delegate, "mandates")
                    .addParameters(WWWFormCodec.parse(queryParams, UTF_8))
                    .build();
        } catch (URISyntaxException e) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to build Pääsuke fetchMandates URL", e);
        }
        requestLogger.logRequest(uri.toString(), HttpMethod.GET.name());
        try {
            ResponseEntity<MandateTriplet> response = webclient.get()
                    .uri(uri)
                    .accept(MediaType.APPLICATION_JSON)
                    .header(XRoadHeaders.CLIENT, xRoadConfigurationProperties.clientId())
                    .header(XRoadHeaders.USER_ID, delegate)
                    .header(XRoadHeaders.MESSAGE_ID, UUID.randomUUID().toString())
                    .retrieve()
                    .toEntity(MandateTriplet.class)
                    .timeout(
                            paasukeConfigurationProperties.requestTimeout(),
                            Mono.error(() -> new HttpTimeoutRuntimeException("Pääsuke request timeout exceeded")))
                    .blockOptional()
                    .orElseThrow();
            MandateTriplet responseBody = response.getBody();
            requestLogger.logResponse(response.getStatusCode().value(), responseBody);
            return responseBody;
        } catch (WebClientResponseException e) {
            requestLogger.logResponse(e.getStatusCode().value(), e.getResponseBodyAsString());
            throw new SsoException(
                    ErrorCode.TECHNICAL_PAASUKE_UNAVAILABLE, "Pääsuke fetchMandates request failed with HTTP error", e);
        } catch (HttpTimeoutRuntimeException e) {
            throw new SsoException(ErrorCode.TECHNICAL_PAASUKE_UNAVAILABLE, "Pääsuke fetchMandates request timed out", e);
        }
    }

    public Person[] fetchRepresentees(@NonNull String delegate, @NonNull String queryParams) {
        URI uri;
        try {
            uri = new URIBuilder(paasukeConfigurationProperties.hostUrl().toURI())
                    .appendPathSegments("delegates", delegate, "representees")
                    .addParameters(WWWFormCodec.parse(queryParams, UTF_8))
                    .build();
        } catch (URISyntaxException e) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to build Pääsuke fetchRepresentees URL", e);
        }
        requestLogger.logRequest(uri.toString(), HttpMethod.GET.name());
        try {
            ResponseEntity<Person[]> response = webclient.get()
                    .uri(uri)
                    .accept(MediaType.APPLICATION_JSON)
                    .header(XRoadHeaders.CLIENT, xRoadConfigurationProperties.clientId())
                    .header(XRoadHeaders.USER_ID, delegate)
                    .header(XRoadHeaders.MESSAGE_ID, UUID.randomUUID().toString())
                    .retrieve()
                    .toEntity(Person[].class)
                    .timeout(
                            paasukeConfigurationProperties.requestTimeout(),
                            Mono.error(() -> new HttpTimeoutRuntimeException("Pääsuke request timeout exceeded")))
                    .blockOptional()
                    .orElseThrow();
            Person[] responseBody = response.getBody();
            requestLogger.logResponse(response.getStatusCode().value(), responseBody);
            return responseBody;
        } catch (WebClientResponseException e) {
            requestLogger.logResponse(e.getStatusCode().value(), e.getResponseBodyAsString());
            throw new SsoException(
                    ErrorCode.TECHNICAL_PAASUKE_UNAVAILABLE, "Pääsuke fetchRepresentees request failed with HTTP error", e);
        } catch (HttpTimeoutRuntimeException e) {
            throw new SsoException(ErrorCode.TECHNICAL_PAASUKE_UNAVAILABLE, "Pääsuke fetchRepresentees request timed out", e);
        }
    }
}
