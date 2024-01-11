package ee.ria.govsso.session.logging;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
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
                .serializationInclusion(JsonInclude.Include.NON_NULL)
                .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
                .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                .addModule(new JavaTimeModule())
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
                } catch (JsonProcessingException ex) {
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
                } catch (JsonProcessingException ex) {
                    throw new IllegalStateException("Unable to convert response body object to JSON string", ex);
                }
            }
            log.info(logMarker, logResponseMessage);
        }

    }

}
