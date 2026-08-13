package ee.ria.govsso.session.token;

import com.nimbusds.jwt.JWTClaimsSet;

import java.text.ParseException;
import java.util.Map;

public record UserAttributes(
        String acr,
        String[] amr,
        String givenName,
        String familyName,
        String birthdate,
        String phoneNumber,
        Boolean phoneNumberVerified) {

    public static UserAttributes fromTaraIdToken(JWTClaimsSet claims) throws ParseException {
        Map<String, Object> profileAttributes = claims.getJSONObjectClaim("profile_attributes");
        return new UserAttributes(
                claims.getStringClaim("acr"),
                claims.getStringArrayClaim("amr"),
                profileAttributes.get("given_name").toString(),
                profileAttributes.get("family_name").toString(),
                profileAttributes.get("date_of_birth").toString(),
                claims.getStringClaim("phone_number"),
                claims.getBooleanClaim("phone_number_verified"));
    }

    public static UserAttributes fromAuthHandoverToken(JWTClaimsSet claims) throws ParseException {
        return new UserAttributes(
                claims.getStringClaim("acr"),
                claims.getStringArrayClaim("amr"),
                claims.getStringClaim("given_name"),
                claims.getStringClaim("family_name"),
                claims.getStringClaim("birthdate"),
                claims.getStringClaim("phone_number"),
                claims.getBooleanClaim("phone_number_verified"));
    }
}
