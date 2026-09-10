package ee.ria.govsso.session.util;

import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import lombok.experimental.UtilityClass;

import java.time.Instant;

@UtilityClass
public class AuthHandoverTokenUtil {

    public static Instant requireAuthHandoverClaim(Instant value, String claimName) {
        if (value == null) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL,
                    "Auth handover token does not contain %s claim".formatted(claimName));
        }
        return value;
    }
}
