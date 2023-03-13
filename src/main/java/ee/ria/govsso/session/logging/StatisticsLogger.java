package ee.ria.govsso.session.logging;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jwt.JWT;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.hydra.OidcContext;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.thymeleaf.util.ArrayUtils;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationState.AUTHENTICATION_CANCELED;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationState.AUTHENTICATION_SUCCESS;
import static java.util.Arrays.stream;
import static net.logstash.logback.marker.Markers.appendFields;

@Slf4j
@Component
public class StatisticsLogger {
    public static final String LOGIN_REQUEST_INFO = "LOGIN_REQUEST_INFO";
    public static final String CONSENT_REQUEST_INFO = "CONSENT_REQUEST_INFO";
    public static final String AUTHENTICATION_REQUEST_TYPE = "AUTHENTICATION_REQUEST_TYPE";
    private final Map<String, String> authenticationTypes = Map.of(
            "smartid", "SMART_ID",
            "mID", "MOBILE_ID",
            "idcard", "ID_CARD",
            "eidas", "EIDAS");

    @SneakyThrows
    public void logAccept(@NonNull AuthenticationRequestType requestType, @NonNull JWT taraIdToken, @NonNull LoginRequestInfo loginRequestInfo) {
        logAccept(requestType, taraIdToken, loginRequestInfo.getClient(), loginRequestInfo.getSessionId(), loginRequestInfo.getOidcContext());
    }

    @SneakyThrows
    public void logAccept(@NonNull AuthenticationRequestType requestType, @NonNull JWT taraIdToken, @NonNull ConsentRequestInfo consentRequestInfo, String sessionId) {
        logAccept(requestType, taraIdToken, consentRequestInfo.getClient(), sessionId, consentRequestInfo.getOidcContext());
    }

    private void logAccept(@NonNull AuthenticationRequestType requestType, @NonNull JWT taraIdToken, @NonNull Client client, @NonNull String sessionId, OidcContext oidcContext) throws ParseException {
        var institution = client.getMetadata().getOidcClient().getInstitution();
        var claims = taraIdToken.getJWTClaimsSet();
        var subject = claims.getSubject();
        var country = subject.substring(0, 2);
        var idCode = subject.substring(2);
        var sid = sessionId;
        var iat = claims.getIssueTime();
        var sessionTime = Instant.now().getEpochSecond() - iat.toInstant().getEpochSecond();
        var acrValues = oidcContext != null ? oidcContext.getAcrValues() : null;
        var grantedAcr = claims.getStringClaim("acr").toUpperCase(Locale.ROOT);
        var amr = stream(claims.getStringArrayClaim("amr"))
                .filter(authenticationTypes::containsKey)
                .map(authenticationTypes::get)
                .findFirst();

        SessionStatistics sessionStatistics = SessionStatistics.builder()
                .clientId(client.getClientId())
                .registryCode(institution.getRegistryCode())
                .sector(institution.getSector())
                .sessionId(sid)
                .sessionStartTime(iat)
                .sessionDuration(sessionTime)
                .country(country)
                .idCode(idCode)
                .authenticationRequestType(requestType)
                .authenticationState(AUTHENTICATION_SUCCESS)
                .grantedAcr(grantedAcr)
                .build();
        amr.ifPresent(sessionStatistics::setAuthenticationType);
        if (!requestType.equals(AuthenticationRequestType.UPDATE_SESSION) && !ArrayUtils.isEmpty(acrValues) && StringUtils.isNotBlank(acrValues[0])) {
            sessionStatistics.setRequestedAcr(acrValues[0].toUpperCase(Locale.ROOT));
        }


        log.info(appendFields(sessionStatistics), "Statistics");
    }

    public void logReject(@NonNull LoginRequestInfo loginRequestInfo, AuthenticationRequestType requestType) {
        var client = loginRequestInfo.getClient();
        var institution = client.getMetadata().getOidcClient().getInstitution();
        var sid = loginRequestInfo.getSessionId();

        SessionStatistics sessionStatistics = SessionStatistics.builder()
                .clientId(client.getClientId())
                .registryCode(institution.getRegistryCode())
                .sector(institution.getSector())
                .sessionId(sid)
                .authenticationRequestType(requestType)
                .authenticationState(AUTHENTICATION_CANCELED)
                .build();

        log.info(appendFields(sessionStatistics), "Statistics");
    }

    public void logError(@NonNull Exception ex, @NonNull ErrorCode errorCode, @NonNull Client
            client, @NonNull String sid, AuthenticationRequestType requestType) {
        var institution = client.getMetadata().getOidcClient().getInstitution();

        SessionStatistics sessionStatistics = SessionStatistics.builder()
                .clientId(client.getClientId())
                .registryCode(institution.getRegistryCode())
                .sector(institution.getSector())
                .sessionId(sid)
                .authenticationRequestType(requestType)
                .authenticationState(AUTHENTICATION_FAILED)
                .errorCode(errorCode)
                .build();

        log.error(appendFields(sessionStatistics), "Statistics", ex);
    }

    enum AuthenticationState {AUTHENTICATION_SUCCESS, AUTHENTICATION_CANCELED, AUTHENTICATION_FAILED}

    public enum AuthenticationRequestType {START_SESSION, CONTINUE_SESSION, UPDATE_SESSION}

    @Builder
    @Data
    static class SessionStatistics {
        @JsonProperty("client.id")
        private String clientId;

        @JsonProperty("institution.registry_code")
        private String registryCode;

        @JsonProperty("institution.sector")
        private String sector;

        @JsonProperty("session.id")
        private String sessionId;

        @JsonProperty("session.start_time")
        private Date sessionStartTime;

        @JsonProperty("session.duration")
        private Long sessionDuration;

        @JsonProperty("authentication.country")
        private String country;

        @JsonProperty("authentication.id_code")
        private String idCode;

        @JsonProperty("authentication.request_type")
        private AuthenticationRequestType authenticationRequestType;

        @JsonProperty("authentication.type")
        private String authenticationType;

        @JsonProperty("authentication.state")
        private AuthenticationState authenticationState;

        @JsonProperty("authentication.requested_acr")
        private String requestedAcr;

        @JsonProperty("authentication.granted_acr")
        private String grantedAcr;

        @JsonProperty("authentication.error_code")
        private ErrorCode errorCode;
    }
}
