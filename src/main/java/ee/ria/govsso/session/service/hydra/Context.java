package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.govsso.session.token.UserAttributes;
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
    @Deprecated
    private boolean isLongLivingSession;
    private SessionType sessionType;
    private String authHandoverToken;
    private UserAttributes userAttributes;

    @JsonIgnore
    public ClientType getInitiator() {
        return switch (this.getSessionType()) {
            case SECURED_APP_SESSION, SECURED_APP_WEB_SESSION -> ClientType.SECURED_APP;
            case WEB_SESSION -> ClientType.DEFAULT;
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
