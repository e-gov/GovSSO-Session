package ee.ria.govsso.session.util;

import com.nimbusds.jwt.JWTClaimNames;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.Metadata;
import ee.ria.govsso.session.token.UserAttributes;
import lombok.experimental.UtilityClass;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import static ee.ria.govsso.session.service.hydra.HydraService.AUTH_TIME_CLAIM;

@UtilityClass
public class AuthHandoverTokenUtil {

    public static boolean clientAcceptsAuthHandover(Client client, UserAttributes userAttributes,
                                                    Duration sessionMaxDuration, Clock clock) {
        Metadata metadata = client.getMetadata();
        if (!metadata.isAllowSecuredAppWebSession()) {
            return false;
        }
        Instant now = Instant.now(clock);
        Instant issuedAt = requireAuthHandoverClaim(userAttributes.tokenIssuedAt(), JWTClaimNames.ISSUED_AT);
        if (Duration.between(issuedAt, now).compareTo(sessionMaxDuration) > 0) {
            return false;
        }
        Instant authTime = requireAuthHandoverClaim(userAttributes.sessionStartTime(), AUTH_TIME_CLAIM);
        Duration securedAppSessionAge = Duration.between(authTime, now);
        Duration securedAppSessionMaxDuration = metadata.getSecuredAppSessionMaxAge();
        if (securedAppSessionMaxDuration != null
                && securedAppSessionAge.compareTo(securedAppSessionMaxDuration) > 0) {
            return false;
        }
        return true;
    }

    public static Instant requireAuthHandoverClaim(Instant value, String claimName) {
        if (value == null) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL,
                    "Auth handover token does not contain %s claim".formatted(claimName));
        }
        return value;
    }
}
