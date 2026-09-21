package ee.ria.govsso.session.token;

import lombok.Builder;

import java.time.Instant;

@Builder
public record UserAttributes(
        String subject,
        Instant tokenIssuedAt,
        Instant sessionStartTime,
        String acr,
        String[] amr,
        String givenName,
        String familyName,
        String birthdate,
        String phoneNumber,
        Boolean phoneNumberVerified) {
}
