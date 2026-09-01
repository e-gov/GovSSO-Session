package ee.ria.govsso.session.token;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.util.DateUtils;

import java.time.Clock;
import java.util.Date;
import java.util.Set;

public class AuthHandoverTokenClaimsVerifier extends DefaultJWTClaimsVerifier<SecurityContext> {

    private static final String CLIENT_ID_CLAIM = "client_id";
    private static final String ACR_CLAIM = "acr";
    private static final String AMR_CLAIM = "amr";
    private static final String AUTH_TIME_CLAIM = "auth_time";
    private static final String BIRTHDATE_CLAIM = "birthdate";
    private static final String FAMILY_NAME_CLAIM = "family_name";
    private static final String GIVEN_NAME_CLAIM = "given_name";
    private static final String INITIATOR_CLAIM = "initiator";
    private static final String SESSION_EXPIRY_CLAIM = "session_expiry";

    private static final Set<String> requiredClaims = Set.of(
            JWTClaimNames.SUBJECT,
            JWTClaimNames.ISSUED_AT,
            JWTClaimNames.EXPIRATION_TIME,
            JWTClaimNames.JWT_ID,
            CLIENT_ID_CLAIM, ACR_CLAIM,
            AMR_CLAIM, AUTH_TIME_CLAIM,
            BIRTHDATE_CLAIM, FAMILY_NAME_CLAIM,
            GIVEN_NAME_CLAIM, INITIATOR_CLAIM,
            SESSION_EXPIRY_CLAIM
    );

    private final Clock clock;

    AuthHandoverTokenClaimsVerifier(String expectedAudience, JWTClaimsSet exactMatchClaims, Clock clock) {
        super(expectedAudience, exactMatchClaims, requiredClaims);
        this.clock = clock;
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, SecurityContext context) throws BadJWTException {
        super.verify(claimsSet, context);
        // Expiration time validation is achieved by the combination of including it in required claims
        // and DefaultJWTClaimsVerifier.verify.
        verifyIssueTime(claimsSet);
    }

    private void verifyIssueTime(JWTClaimsSet claimsSet) throws BadJWTException {
        Date issueTime = claimsSet.getIssueTime();
        if (DateUtils.isAfter(issueTime, currentTime(), getMaxClockSkew())) {
            throw new BadJWTException("JWT issue time ahead of current time");
        }
    }

    @Override
    protected Date currentTime() {
        return Date.from(clock.instant());
    }
}
