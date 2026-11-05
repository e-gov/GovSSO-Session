package ee.ria.govsso.session.token;

import ee.ria.govsso.session.service.hydra.ClientType;
import ee.ria.govsso.session.service.hydra.Context;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

import static ee.ria.govsso.session.service.helper.ClientScopes.SCOPE_PHONE;

@Component
public class AccessTokenClaimsFactory {

    public AccessTokenClaims from(UserAttributes userAttributes, List<String> scopes, Context context, Instant authenticatedAt) {
        ClientType initiator = switch (context.getInitiator()) {
            case SECURED_APP -> ClientType.SECURED_APP;
            case DEFAULT -> null;
        };
        AccessTokenClaims.AccessTokenClaimsBuilder builder = AccessTokenClaims.builder()
                .acr(userAttributes.acr())
                .amr(userAttributes.amr())
                .givenName(userAttributes.givenName())
                .familyName(userAttributes.familyName())
                .birthdate(userAttributes.birthdate())
                .initiator(initiator)
                .authTime(getSecuredAppAuthTime(userAttributes, context, authenticatedAt));
        if (scopes.contains(SCOPE_PHONE)) {
            builder
                    .phoneNumber(userAttributes.phoneNumber())
                    .phoneNumberVerified(userAttributes.phoneNumberVerified());
        }
        return builder.build();
    }

    private static Instant getSecuredAppAuthTime(UserAttributes userAttributes, Context context, Instant authenticatedAt) {
        return switch (context.getSessionTypeOrFallback()) {
            case SECURED_APP_SESSION -> authenticatedAt;
            case SECURED_APP_WEB_SESSION -> userAttributes.taraAuthTime();
            case WEB_SESSION -> null;
        };
    }

}
