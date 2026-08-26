package ee.ria.govsso.session.token;

import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.govsso.session.service.hydra.SessionType;
import lombok.Builder;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static ee.ria.govsso.session.service.hydra.HydraService.AUTH_TIME_CLAIM;

@Builder
public record UserAttributes(
        Source source,
        String subject,
        Instant issuedAt,
        Instant authTime,
        String acr,
        String[] amr,
        String givenName,
        String familyName,
        String birthdate,
        String phoneNumber,
        Boolean phoneNumberVerified) {

    public enum Source {TARA_ID_TOKEN, AUTH_HANDOVER_TOKEN}

    public Instant sessionStartTime() {
        return switch (source) {
            case TARA_ID_TOKEN -> issuedAt;
            case AUTH_HANDOVER_TOKEN -> authTime;
        };
    }

    public static UserAttributes from(SessionType sessionType, JWTClaimsSet claims) throws ParseException {
        return switch (sessionType) {
            case SECURED_APP_WEB_SESSION -> fromAuthHandoverToken(claims);
            case WEB_SESSION, SECURED_APP_SESSION -> fromTaraIdToken(claims);
        };
    }

    public static UserAttributes fromTaraIdToken(JWTClaimsSet claims) throws ParseException {
        Map<String, Object> profileAttributes = claims.getJSONObjectClaim("profile_attributes");
        return UserAttributes.builder()
                .source(Source.TARA_ID_TOKEN)
                .subject(claims.getSubject())
                .issuedAt(toInstant(claims.getIssueTime()))
                .authTime(toInstant(claims.getDateClaim(AUTH_TIME_CLAIM)))
                .acr(claims.getStringClaim("acr"))
                .amr(claims.getStringArrayClaim("amr"))
                .givenName(toStringOrNull(profileAttributes.get("given_name")))
                .familyName(toStringOrNull(profileAttributes.get("family_name")))
                .birthdate(toStringOrNull(profileAttributes.get("date_of_birth")))
                .phoneNumber(claims.getStringClaim("phone_number"))
                .phoneNumberVerified(claims.getBooleanClaim("phone_number_verified"))
                .build();
    }

    public static UserAttributes fromAuthHandoverToken(JWTClaimsSet claims) throws ParseException {
        return UserAttributes.builder()
                .source(Source.AUTH_HANDOVER_TOKEN)
                .subject(claims.getSubject())
                .issuedAt(toInstant(claims.getIssueTime()))
                .authTime(toInstant(claims.getDateClaim(AUTH_TIME_CLAIM)))
                .acr(claims.getStringClaim("acr"))
                .amr(claims.getStringArrayClaim("amr"))
                .givenName(claims.getStringClaim("given_name"))
                .familyName(claims.getStringClaim("family_name"))
                .birthdate(claims.getStringClaim("birthdate"))
                .phoneNumber(claims.getStringClaim("phone_number"))
                .phoneNumberVerified(claims.getBooleanClaim("phone_number_verified"))
                .build();
    }

    private static Instant toInstant(Date date) {
        return date == null ? null : date.toInstant();
    }

    private static String toStringOrNull(Object value) {
        return value == null ? null : value.toString();
    }
}
