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

    private static final String SCOPE_CLAIM = "scope";
    private static final String CLIENT_ID_CLAIM = "client_id";

    private final Clock clock;

    AuthHandoverTokenClaimsVerifier(String expectedIssuer, String expectedAudience, String expectedScope,
                                    Clock clock) {
        super(expectedAudience,
                new JWTClaimsSet.Builder()
                        .issuer(expectedIssuer)
                        .claim(SCOPE_CLAIM, expectedScope)
                        .build(),
                Set.of(JWTClaimNames.SUBJECT,
                        JWTClaimNames.ISSUED_AT,
                        JWTClaimNames.EXPIRATION_TIME,
                        CLIENT_ID_CLAIM));
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
