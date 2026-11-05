package ee.ria.govsso.session.service.authhandover;

import com.nimbusds.jwt.JWTClaimNames;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.LevelOfAssurance;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.hydra.Metadata;
import ee.ria.govsso.session.token.UserAttributes;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import static ee.ria.govsso.session.service.hydra.HydraService.AUTH_TIME_CLAIM;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthHandoverAcceptancePolicy {

    private final SsoConfigurationProperties ssoConfigurationProperties;
    private final Clock clock;

    public enum Result {
        ACCEPTED,
        SECURED_APP_WEB_SESSION_NOT_ALLOWED,
        AUTH_HANDOVER_EXPIRED,
        SECURED_APP_SESSION_EXPIRED,
        INSUFFICIENT_ACR
    }

    public boolean clientAcceptsAuthHandover(Client client, UserAttributes userAttributes) {
        return evaluateClientAcceptsAuthHandover(client, userAttributes) == Result.ACCEPTED;
    }

    public Result evaluateClientAcceptsAuthHandover(Client client, UserAttributes userAttributes) {
        Result result = evaluate(client.getMetadata(), userAttributes);
        isAccepted(client, userAttributes, result);
        return result;
    }

    public boolean clientAcceptsAuthHandoverLogin(LoginRequestInfo loginRequestInfo, UserAttributes userAttributes) {
        Client client = loginRequestInfo.getClient();
        Result result = evaluate(client.getMetadata(), userAttributes);
        if (result == Result.ACCEPTED && !isSessionAcrHigherOrEqualToLoginRequestAcr(loginRequestInfo, userAttributes)) {
            result = Result.INSUFFICIENT_ACR;
        }
        return isAccepted(client, userAttributes, result);
    }

    private static boolean isSessionAcrHigherOrEqualToLoginRequestAcr(LoginRequestInfo loginRequestInfo,
                                                                      UserAttributes userAttributes) {
        LevelOfAssurance requestAcr = loginRequestInfo.getAcr();
        LevelOfAssurance requiredAcr = requestAcr != null ? requestAcr : LevelOfAssurance.DEFAULT;
        LevelOfAssurance sessionAcr = LevelOfAssurance.findByAcrName(userAttributes.acr());
        return sessionAcr != null && sessionAcr.getAcrLevel() >= requiredAcr.getAcrLevel();
    }

    private boolean isAccepted(Client client, UserAttributes userAttributes, Result result) {
        if (result == Result.ACCEPTED) {
            return true;
        }
        log.info(append("auth_handover.target_client_id", client.getClientId())
                        .and(append("auth_handover.auth_handover_time", userAttributes.authHandoverTime()))
                        .and(append("auth_handover.tara_auth_time", userAttributes.taraAuthTime()))
                        .and(append("auth_handover.result", result)),
                "Client does not accept auth handover: {}", result);
        return false;
    }

    private Result evaluate(Metadata metadata, UserAttributes userAttributes) {
        if (!metadata.isAllowSecuredAppWebSession()) {
            return Result.SECURED_APP_WEB_SESSION_NOT_ALLOWED;
        }
        Instant now = Instant.now(clock);
        Instant authHandoverTime = requireAuthHandoverClaim(userAttributes.authHandoverTime(), JWTClaimNames.ISSUED_AT);
        if (Duration.between(authHandoverTime, now).compareTo(ssoConfigurationProperties.getSessionMaxDuration()) > 0) {
            return Result.AUTH_HANDOVER_EXPIRED;
        }
        Duration securedAppSessionMaxDuration = metadata.getSecuredAppSessionMaxAge();
        if (securedAppSessionMaxDuration != null) {
            Instant authTime = requireAuthHandoverClaim(userAttributes.taraAuthTime(), AUTH_TIME_CLAIM);
            Duration securedAppSessionAge = Duration.between(authTime, now);
            if (securedAppSessionAge.compareTo(securedAppSessionMaxDuration) > 0) {
                return Result.SECURED_APP_SESSION_EXPIRED;
            }
        }
        return Result.ACCEPTED;
    }

    private static Instant requireAuthHandoverClaim(Instant value, String claimName) {
        if (value == null) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL,
                    "Auth handover token does not contain %s claim".formatted(claimName));
        }
        return value;
    }
}
