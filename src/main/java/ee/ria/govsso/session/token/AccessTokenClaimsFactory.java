package ee.ria.govsso.session.token;

import ee.ria.govsso.session.service.hydra.Context;
import ee.ria.govsso.session.util.SecureAppUtil;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

import static ee.ria.govsso.session.service.helper.ClientScopes.SCOPE_PHONE;

@Component
public class AccessTokenClaimsFactory {

    public AccessTokenClaims from(UserAttributes userAttributes, List<String> scopes, Context context, Instant authenticatedAt) {
        AccessTokenClaims.AccessTokenClaimsBuilder builder = AccessTokenClaims.builder()
                .acr(userAttributes.acr())
                .amr(userAttributes.amr())
                .givenName(userAttributes.givenName())
                .familyName(userAttributes.familyName())
                .birthdate(userAttributes.birthdate())
                .initiator(context.getInitiator())
                .authTime(SecureAppUtil.isSecuredAppSession(context) ? authenticatedAt : null);
        if (scopes.contains(SCOPE_PHONE)) {
            builder
                    .phoneNumber(userAttributes.phoneNumber())
                    .phoneNumberVerified(userAttributes.phoneNumberVerified());
        }
        return builder.build();
    }

}
