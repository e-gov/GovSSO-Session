package ee.ria.govsso.session.token;

import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.govsso.session.service.hydra.ClientType;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Component
public class AccessTokenClaimsFactory {

    public AccessTokenClaims from(JWTClaimsSet taraIdTokenClaims, List<String> scopes, boolean isLongLivingSession, Instant authenticatedAt)
            throws ParseException {
        Map<String, Object> profileAttributes = taraIdTokenClaims.getJSONObjectClaim("profile_attributes");
        AccessTokenClaims.AccessTokenClaimsBuilder builder = AccessTokenClaims.builder()
                .acr(taraIdTokenClaims.getStringClaim("acr"))
                .amr(taraIdTokenClaims.getStringArrayClaim("amr"))
                .givenName(profileAttributes.get("given_name").toString())
                .familyName(profileAttributes.get("family_name").toString())
                .birthdate(profileAttributes.get("date_of_birth").toString())
                .initiator(isLongLivingSession ? ClientType.SECURED_APP : null)
                .authTime(authenticatedAt);
        if (scopes.contains("phone")) {
            builder
                    .phoneNumber(taraIdTokenClaims.getStringClaim("phone_number"))
                    .phoneNumberVerified(taraIdTokenClaims.getBooleanClaim("phone_number_verified"));
        }
        return builder.build();
    }

}
