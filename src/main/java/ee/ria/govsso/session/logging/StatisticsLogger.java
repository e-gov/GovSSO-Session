package ee.ria.govsso.session.logging;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jwt.JWT;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import ee.ria.govsso.session.service.hydra.LevelOfAssurance;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.token.UserAttributes;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationState.AUTHENTICATION_CANCELED;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.govsso.session.util.LocaleUtil.DEFAULT_LANGUAGE;
import static java.util.Arrays.stream;
import static net.logstash.logback.marker.Markers.appendFields;

@Slf4j
@Component
public class StatisticsLogger {
    public static final String LOGIN_REQUEST_INFO = "LOGIN_REQUEST_INFO";
    public static final String CONSENT_REQUEST_INFO = "CONSENT_REQUEST_INFO";
    public static final String AUTHENTICATION_REQUEST_TYPE = "AUTHENTICATION_REQUEST_TYPE";
    public static final String LOG_MESSAGE = "Statistics";
    private final Map<String, String> authenticationTypes = Map.of(
            "smartid", "SMART_ID",
            "mID", "MOBILE_ID",
            "idcard", "ID_CARD",
            "eidas", "EIDAS");

    @SneakyThrows
    public void logAccept(
            @NonNull AuthenticationRequestType requestType, @NonNull JWT taraIdToken,
            @NonNull LoginRequestInfo loginRequestInfo) {
        var claims = taraIdToken.getJWTClaimsSet();
        logAccept(
                requestType, claims.getSubject(), claims.getIssueTime().toInstant(), claims.getStringClaim("acr"),
                claims.getStringArrayClaim("amr"), loginRequestInfo.getClient(), loginRequestInfo.getSessionId(),
                loginRequestInfo.getAcr());
    }

    public void logAccept(
            @NonNull AuthenticationRequestType requestType, @NonNull UserAttributes userAttributes,
            @NonNull LoginRequestInfo loginRequestInfo) {
        logAccept(
                requestType, userAttributes.subject(), userAttributes.sessionStartTime(), userAttributes.acr(),
                userAttributes.amr(), loginRequestInfo.getClient(), loginRequestInfo.getSessionId(),
                loginRequestInfo.getAcr());
    }

    public void logAccept(
            @NonNull AuthenticationRequestType requestType, @NonNull UserAttributes userAttributes,
            @NonNull ConsentRequestInfo consentRequestInfo, String sessionId) {
        logAccept(
                requestType, userAttributes.subject(), userAttributes.sessionStartTime(), userAttributes.acr(),
                userAttributes.amr(), consentRequestInfo.getClient(), sessionId, null);
    }

    private void logAccept(
            @NonNull AuthenticationRequestType requestType, @NonNull String subject, @NonNull Instant sessionStartTime,
            @NonNull String acr, @NonNull String[] amrClaim, @NonNull Client client, @NonNull String sessionId,
            LevelOfAssurance requestAcr) {
        var oidcClient = client.getMetadata().getOidcClient();
        var institution = oidcClient.getInstitution();
        var country = subject.substring(0, 2);
        var idCode = subject.substring(2);
        var sessionTime = Instant.now().getEpochSecond() - sessionStartTime.getEpochSecond();
        var grantedAcr = acr.toUpperCase(Locale.ROOT);
        var amr = stream(amrClaim)
                .filter(authenticationTypes::containsKey)
                .map(authenticationTypes::get)
                .findFirst();

        SessionStatistics sessionStatistics = SessionStatistics.builder()
                .clientId(client.getClientId())
                .clientName(oidcClient.getNameTranslations().get(DEFAULT_LANGUAGE))
                .clientShortName(oidcClient.getShortNameTranslations().get(DEFAULT_LANGUAGE))
                .registryCode(institution.getRegistryCode())
                .sector(institution.getSector())
                .sessionId(sessionId)
                .sessionStartTime(Date.from(sessionStartTime))
                .sessionDuration(sessionTime)
                .country(country)
                .idCode(idCode)
                .authenticationRequestType(requestType)
                .authenticationState(AUTHENTICATION_SUCCESS)
                .grantedAcr(grantedAcr)
                .build();
        amr.ifPresent(sessionStatistics::setAuthenticationType);
        if (requestAcr != null) {
            sessionStatistics.setRequestedAcr(requestAcr.name());
        }

        log.info(appendFields(sessionStatistics), LOG_MESSAGE);
    }

    public void logReject(@NonNull LoginRequestInfo loginRequestInfo, AuthenticationRequestType requestType) {
        var client = loginRequestInfo.getClient();
        var oidcClient = client.getMetadata().getOidcClient();
        var institution = oidcClient.getInstitution();
        var sid = loginRequestInfo.getSessionId();

        SessionStatistics sessionStatistics = SessionStatistics.builder()
                .clientId(client.getClientId())
                .clientName(oidcClient.getNameTranslations().get(DEFAULT_LANGUAGE))
                .clientShortName(oidcClient.getShortNameTranslations().get(DEFAULT_LANGUAGE))
                .registryCode(institution.getRegistryCode())
                .sector(institution.getSector())
                .sessionId(sid)
                .authenticationRequestType(requestType)
                .authenticationState(AUTHENTICATION_CANCELED)
                .build();

        log.info(appendFields(sessionStatistics), LOG_MESSAGE);
    }

    public void logError(@NonNull Exception ex, @NonNull ErrorCode errorCode, @NonNull Client
            client, @NonNull String sid, AuthenticationRequestType requestType) {
        var oidcClient = client.getMetadata().getOidcClient();
        var institution = oidcClient.getInstitution();

        SessionStatistics sessionStatistics = SessionStatistics.builder()
                .clientId(client.getClientId())
                .clientName(oidcClient.getNameTranslations().get(DEFAULT_LANGUAGE))
                .clientShortName(oidcClient.getShortNameTranslations().get(DEFAULT_LANGUAGE))
                .registryCode(institution.getRegistryCode())
                .sector(institution.getSector())
                .sessionId(sid)
                .authenticationRequestType(requestType)
                .authenticationState(AUTHENTICATION_FAILED)
                .errorCode(errorCode)
                .build();

        log.error(appendFields(sessionStatistics), LOG_MESSAGE, ex);
    }

    enum AuthenticationState {AUTHENTICATION_SUCCESS, AUTHENTICATION_CANCELED, AUTHENTICATION_FAILED}

    public enum AuthenticationRequestType {START_SESSION, CONTINUE_SESSION, UPDATE_SESSION, AUTH_HANDOVER}

    @Builder
    @Data
    static class SessionStatistics {
        @JsonProperty("client.id")
        private String clientId;

        @JsonProperty("client.name")
        private String clientName;

        @JsonProperty("client.short_name")
        private String clientShortName;

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
