package ee.ria.govsso.session.token;

import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.govsso.session.service.hydra.LoginSessionInfo;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Component
public class UserAttributesFactory {

    public UserAttributes fromTaraIdToken(JWTClaimsSet claims) throws ParseException {
        Map<String, Object> profileAttributes = claims.getJSONObjectClaim("profile_attributes");
        if (profileAttributes == null) {
            profileAttributes = Map.of();
        }
        return UserAttributes.builder()
                .subject(claims.getSubject())
                .taraAuthTime(toInstant(claims.getIssueTime()))
                .acr(claims.getStringClaim("acr"))
                .amr(claims.getStringListClaim("amr"))
                .givenName(toStringOrNull(profileAttributes.get("given_name")))
                .familyName(toStringOrNull(profileAttributes.get("family_name")))
                .birthdate(toStringOrNull(profileAttributes.get("date_of_birth")))
                .phoneNumber(claims.getStringClaim("phone_number"))
                .phoneNumberVerified(claims.getBooleanClaim("phone_number_verified"))
                .build();
    }

    public UserAttributes fromAuthHandoverToken(JWTClaimsSet claims, LoginSessionInfo loginSessionInfo) throws ParseException {
        return UserAttributes.builder()
                .subject(loginSessionInfo.getSubject())
                .authHandoverTime(toInstant(claims.getIssueTime()))
                .taraAuthTime(loginSessionInfo.getAuthTime())
                .acr(loginSessionInfo.getAcr())
                .amr(loginSessionInfo.getAmr())
                .givenName(loginSessionInfo.getGivenName())
                .familyName(loginSessionInfo.getFamilyName())
                .birthdate(loginSessionInfo.getBirthdate())
                .phoneNumber(loginSessionInfo.getPhoneNumber())
                .phoneNumberVerified(loginSessionInfo.getPhoneNumberVerified())
                .build();
    }

    private static Instant toInstant(Date date) {
        return date == null ? null : date.toInstant();
    }

    private static String toStringOrNull(Object value) {
        return value == null ? null : value.toString();
    }
}
