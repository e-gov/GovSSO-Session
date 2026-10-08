package ee.ria.govsso.session.token;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthHandoverTokenClaimsVerifierTest {

    private static final Instant NOW = Instant.parse("2026-10-07T10:00:00Z");
    private static final String ISSUER = "https://govsso.localhost:15443";
    private static final String SCOPE = "auth_handover";

    private final AuthHandoverTokenClaimsVerifier verifier = createVerifier();

    @Test
    void verify_WhenSubjectClaimIsMissing_DoesNotThrow() {
        JWTClaimsSet claims = validClaims().build();

        assertDoesNotThrow(() -> verifier.verify(claims, null));
    }

    @Test
    void verify_WhenSubjectClaimIsPresent_DoesNotThrow() {
        JWTClaimsSet claims = validClaims().subject("EE60001019906").build();

        assertDoesNotThrow(() -> verifier.verify(claims, null));
    }

    @Test
    void verify_WhenSidClaimIsMissing_ThrowsBadJWTException() {
        JWTClaimsSet claims = baseClaims().build();

        assertThrows(BadJWTException.class, () -> verifier.verify(claims, null));
    }

    @Test
    void verify_WhenIssueTimeIsAheadOfCurrentTime_ThrowsBadJWTException() {
        JWTClaimsSet claims = validClaims()
                .issueTime(Date.from(NOW.plusSeconds(60)))
                .build();

        assertThrows(BadJWTException.class, () -> verifier.verify(claims, null));
    }

    private static AuthHandoverTokenClaimsVerifier createVerifier() {
        AuthHandoverTokenClaimsVerifier claimsVerifier = new AuthHandoverTokenClaimsVerifier(
                new JWTClaimsSet.Builder()
                        .issuer(ISSUER)
                        .claim("scope", SCOPE)
                        .audience(List.of(ISSUER))
                        .build(),
                Clock.fixed(NOW, ZoneOffset.UTC));
        claimsVerifier.setMaxClockSkew(0);
        return claimsVerifier;
    }

    private static JWTClaimsSet.Builder validClaims() {
        return baseClaims().claim("sid", "sid-1");
    }

    private static JWTClaimsSet.Builder baseClaims() {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .claim("scope", SCOPE)
                .audience(List.of(ISSUER))
                .issueTime(Date.from(NOW.minusSeconds(10)))
                .expirationTime(Date.from(NOW.plusSeconds(300)))
                .jwtID("jti-1")
                .claim("client_id", "client-1");
    }
}
