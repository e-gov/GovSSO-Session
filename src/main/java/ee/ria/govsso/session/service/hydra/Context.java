package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.govsso.session.token.UserAttributes;
import ee.ria.govsso.session.token.UserAttributesFactory;
import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.text.ParseException;
import java.util.Objects;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Context {

    private String taraIdToken;
    private String ipAddress;
    private String userAgent;
    private String ipCountry;
    // TODO Remove after fully migrating to SessionType
    private boolean isLongLivingSession;
    private SessionType sessionType;
    private String authHandoverToken;
    private UserAttributes userAttributes;

    // TODO Temporary solution. Remove after all sessions created before session type was added to context have
    //  expired, and instead throw when session type is missing.
    @JsonIgnore
    public SessionType getSessionTypeOrFallback() {
        SessionType sessionType = this.getSessionType();
        if (sessionType != null) {
            return sessionType;
        }
        return this.isLongLivingSession() ? SessionType.SECURED_APP_SESSION : SessionType.WEB_SESSION;
    }

    // TODO Temporary solution. Remove after all sessions created before user attributes were added to context have
    //  expired, and instead throw when user attributes are missing.
    public UserAttributes getUserAttributesOrFallback(UserAttributesFactory userAttributesFactory)
            throws ParseException {
        UserAttributes userAttributes = this.getUserAttributes();
        if (userAttributes != null) {
            return userAttributes;
        }
        return switch (this.getSessionTypeOrFallback()) {
            case SECURED_APP_WEB_SESSION ->
                    userAttributesFactory.fromAuthHandoverToken(getAuthHandoverTokenJwt().getJWTClaimsSet());
            case WEB_SESSION, SECURED_APP_SESSION ->
                    userAttributesFactory.fromTaraIdToken(getTaraIdTokenJwt().getJWTClaimsSet());
        };
    }

    @JsonIgnore
    public SignedJWT getAuthHandoverTokenJwt() throws ParseException {
        return parseRequiredToken(this.getAuthHandoverToken(), "an auth handover token");
    }

    @JsonIgnore
    public SignedJWT getTaraIdTokenJwt() throws ParseException {
        return parseRequiredToken(this.getTaraIdToken(), "a TARA ID token");
    }

    private static SignedJWT parseRequiredToken(String token, String tokenDescription) throws ParseException {
        Objects.requireNonNull(token, "Session context does not contain %s".formatted(tokenDescription));
        return SignedJWT.parse(token);
    }
}
