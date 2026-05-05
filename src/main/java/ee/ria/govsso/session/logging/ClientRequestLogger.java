package ee.ria.govsso.session.logging;

import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import net.logstash.logback.marker.LogstashMarker;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;

import java.util.ArrayList;
import java.util.List;

import static net.logstash.logback.marker.Markers.append;

public class ClientRequestLogger {

    private final org.slf4j.Logger log;

    private static final String PROP_URL_FULL = "url.full";
    private static final String PROP_REQUEST_METHOD = "http.request.method";
    private static final String PROP_REQUEST_BODY_CONTENT = "http.request.body.content";
    private static final String PROP_REQUEST_HEADER = "http.request.header";

    private static final String PROP_RESPONSE_BODY_CONTENT = "http.response.body.content";
    private static final String PROP_RESPONSE_STATUS_CODE = "http.response.status_code";
    private static final String PROP_RESPONSE_HEADER = "http.response.header";

    private final String logRequestMessage;
    private final String logResponseMessage;

    private final ObjectMapper objectMapper;

    public enum Service {
        ALERTS,
        TARA,
        HYDRA,
        PAASUKE,
    }

    public ClientRequestLogger(Class<?> classToBeLogged, Service service) {
        log = org.slf4j.LoggerFactory.getLogger(classToBeLogged);
        logRequestMessage = String.format("%s request", service.name());
        logResponseMessage = String.format("%s response", service.name());
        objectMapper = JsonMapper
                .builder()
                .changeDefaultPropertyInclusion(incl -> incl
                        .withValueInclusion(JsonInclude.Include.NON_NULL)
                        .withContentInclusion(JsonInclude.Include.NON_NULL))
                .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
                .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                .build();
    }

    @Deprecated
    public void logRequest(String requestUrl, String httpMethod) {
        request(httpMethod, requestUrl)
                .log();
    }

    @Deprecated
    public void logRequest(String requestUrl, String httpMethod, Object requestBodyObject) {
        request(httpMethod, requestUrl)
                .body(requestBodyObject)
                .log();
    }

    @Deprecated
    public void logResponse(int httpStatusCode) {
        response(httpStatusCode)
                .log();
    }

    @Deprecated
    public void logResponse(int httpStatusCode, Object responseBodyObject) {
        response(httpStatusCode)
                .body(responseBodyObject)
                .log();
    }

    public Request request(String httpMethod, String url) {
        return new Request(httpMethod, url);
    }

    public Request request(HttpMethod httpMethod, String url) {
        return new Request(httpMethod.name(), url);
    }

    public Response response(int statusCode) {
        return new Response(statusCode);
    }

    public Response response(HttpStatusCode status) {
        return new Response(status.value());
    }

    @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
    public class Request {

        private final @NonNull String httpMethod;
        private final @NonNull String url;
        private final List<Pair<String, String >> headers = new ArrayList<>();
        private Object body;

        public Request header(@NonNull String name, String value) {
            if (value == null) {
                return this;
            }
            this.headers.add(Pair.of(name, value));
            return this;
        }

        public Request body(Object body) {
            this.body = body;
            return this;
        }

        public void log() {
            LogstashMarker logMarker = append(PROP_REQUEST_METHOD, httpMethod)
                    .and(append(PROP_URL_FULL, url));
            for (Pair<String, String> header : headers) {
                String fieldName = PROP_REQUEST_HEADER + "." + header.getKey();
                logMarker.and(append(fieldName, header.getValue()));
            }
            if (body != null) {
                try {
                    String requestBodyJson = objectMapper.writeValueAsString(body);
                    logMarker.and(append(PROP_REQUEST_BODY_CONTENT, requestBodyJson));
                } catch (JacksonException ex) {
                    throw new IllegalStateException("Unable to convert request body object to JSON string", ex);
                }
            }
            log.info(logMarker, logRequestMessage);
        }

    }

    @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
    public class Response {

        private final int statusCode;
        private final List<Pair<String, String>> headers = new ArrayList<>();
        private Object body;

        public Response header(@NonNull String name, String value) {
            if (value == null) {
                return this;
            }
            this.headers.add(Pair.of(name, value));
            return this;
        }

        public Response body(Object body) {
            this.body = body;
            return this;
        }

        public void log() {
            LogstashMarker logMarker = append(PROP_RESPONSE_STATUS_CODE, statusCode);
            for (Pair<String, String> header : headers) {
                String fieldName = PROP_RESPONSE_HEADER + "." + header.getKey();
                logMarker.and(append(fieldName, header.getValue()));
            }
            if (body != null) {
                try {
                    String responseBodyJson = objectMapper.writeValueAsString(body);
                    logMarker.and(append(PROP_RESPONSE_BODY_CONTENT, responseBodyJson));
                } catch (JacksonException ex) {
                    throw new IllegalStateException("Unable to convert response body object to JSON string", ex);
                }
            }
            log.info(logMarker, logResponseMessage);
        }

    }

}
