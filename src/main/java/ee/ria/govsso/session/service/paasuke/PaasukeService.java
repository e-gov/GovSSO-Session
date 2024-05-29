package ee.ria.govsso.session.service.paasuke;

import ee.ria.govsso.session.configuration.properties.PaasukeConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.XRoadConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.HttpTimeoutRuntimeException;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.ClientRequestLogger;
import ee.ria.govsso.session.xroad.XRoadHeaders;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.hc.core5.net.WWWFormCodec;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
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
import java.util.function.Consumer;

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

    @Getter
    private volatile Boolean lastRequestToPaasukeSuccessful = null;

    public MandateTriplet fetchMandates(
            @NonNull String representee, @NonNull String delegate, @NonNull String queryParams,
            @NonNull PaasukeGovssoClient govssoClient) {
        URI uri;
        try {
            uri = new URIBuilder(paasukeConfigurationProperties.hostUrl().toURI())
                    .appendPathSegments("representees", representee, "delegates", delegate, "mandates")
                    .addParameters(WWWFormCodec.parse(queryParams, UTF_8))
                    .build();
        } catch (URISyntaxException e) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to build Pääsuke fetchMandates URL", e);
        }
        String outgoingXroadMessageId = UUID.randomUUID().toString();
        requestLogger.request(HttpMethod.GET, uri.toString())
                .header(XRoadHeaders.MESSAGE_ID, outgoingXroadMessageId)
                .log();
        try {
            ResponseEntity<MandateTriplet> response = webclient.get()
                    .uri(uri)
                    .accept(MediaType.APPLICATION_JSON)
                    .header(XRoadHeaders.CLIENT, xRoadConfigurationProperties.clientId())
                    .header(XRoadHeaders.USER_ID, delegate)
                    .header(XRoadHeaders.MESSAGE_ID, outgoingXroadMessageId)
                    .headers(govssoClientHeaders(govssoClient))
                    .retrieve()
                    .toEntity(MandateTriplet.class)
                    .timeout(
                            paasukeConfigurationProperties.requestTimeout(),
                            Mono.error(() -> new HttpTimeoutRuntimeException("Pääsuke request timeout exceeded")))
                    .blockOptional()
                    .orElseThrow();
            lastRequestToPaasukeSuccessful = true;
            MandateTriplet responseBody = response.getBody();
            requestLogger.response(response.getStatusCode())
                    .body(responseBody)
                    .header(XRoadHeaders.MESSAGE_ID, response.getHeaders().getFirst(XRoadHeaders.MESSAGE_ID))
                    .log();
            return responseBody;
        } catch (WebClientResponseException e) {
            requestLogger.response(e.getStatusCode())
                    .body(e.getResponseBodyAsString())
                    .header(XRoadHeaders.MESSAGE_ID, e.getHeaders().getFirst(XRoadHeaders.MESSAGE_ID))
                    .log();
            lastRequestToPaasukeSuccessful = false;
            throw new SsoException(
                    ErrorCode.TECHNICAL_PAASUKE_UNAVAILABLE, "Pääsuke fetchMandates request failed with HTTP error", e);
        } catch (HttpTimeoutRuntimeException e) {
            lastRequestToPaasukeSuccessful = false;
            throw new SsoException(ErrorCode.TECHNICAL_PAASUKE_UNAVAILABLE, "Pääsuke fetchMandates request timed out", e);
        }
    }

    public Person[] fetchRepresentees(
            @NonNull String delegate, @NonNull String queryParams, @NonNull PaasukeGovssoClient govssoClient) {
        URI uri;
        try {
            uri = new URIBuilder(paasukeConfigurationProperties.hostUrl().toURI())
                    .appendPathSegments("delegates", delegate, "representees")
                    .addParameters(WWWFormCodec.parse(queryParams, UTF_8))
                    .build();
        } catch (URISyntaxException e) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to build Pääsuke fetchRepresentees URL", e);
        }
        String outgoingXroadMessageId = UUID.randomUUID().toString();
        requestLogger.request(HttpMethod.GET, uri.toString())
                .header(XRoadHeaders.MESSAGE_ID, outgoingXroadMessageId)
                .log();
        try {
            ResponseEntity<Person[]> response = webclient.get()
                    .uri(uri)
                    .accept(MediaType.APPLICATION_JSON)
                    .header(XRoadHeaders.CLIENT, xRoadConfigurationProperties.clientId())
                    .header(XRoadHeaders.USER_ID, delegate)
                    .header(XRoadHeaders.MESSAGE_ID, outgoingXroadMessageId)
                    .headers(govssoClientHeaders(govssoClient))
                    .retrieve()
                    .toEntity(Person[].class)
                    .timeout(
                            paasukeConfigurationProperties.requestTimeout(),
                            Mono.error(() -> new HttpTimeoutRuntimeException("Pääsuke request timeout exceeded")))
                    .blockOptional()
                    .orElseThrow();
            lastRequestToPaasukeSuccessful = true;
            Person[] responseBody = response.getBody();
            requestLogger.response(response.getStatusCode())
                    .body(responseBody)
                    .header(XRoadHeaders.MESSAGE_ID, response.getHeaders().getFirst(XRoadHeaders.MESSAGE_ID))
                    .log();
            return responseBody;
        } catch (WebClientResponseException e) {
            requestLogger.response(e.getStatusCode())
                    .body(e.getResponseBodyAsString())
                    .header(XRoadHeaders.MESSAGE_ID, e.getHeaders().getFirst(XRoadHeaders.MESSAGE_ID))
                    .log();
            lastRequestToPaasukeSuccessful = false;
            throw new SsoException(
                    ErrorCode.TECHNICAL_PAASUKE_UNAVAILABLE, "Pääsuke fetchRepresentees request failed with HTTP error", e);
        } catch (HttpTimeoutRuntimeException e) {
            lastRequestToPaasukeSuccessful = false;
            throw new SsoException(ErrorCode.TECHNICAL_PAASUKE_UNAVAILABLE, "Pääsuke fetchRepresentees request timed out", e);
        }
    }

    private Consumer<HttpHeaders> govssoClientHeaders(@NonNull PaasukeGovssoClient govssoClient) {
        return headers -> {
            headers.add(PaasukeHeaders.INSTITUTION, govssoClient.institution());
            headers.add(PaasukeHeaders.CLIENT_ID, govssoClient.clientId());
        };
    }
}
