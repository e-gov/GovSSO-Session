package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.databind.PropertyNamingStrategies.SnakeCaseStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@JsonNaming(SnakeCaseStrategy.class)
public final class RefreshTokenHookResponse {
    private Session session;

    @Builder
    public RefreshTokenHookResponse(String sessionId, String givenName, String familyName, String birthDate, boolean refreshRememberFor, int rememberFor, boolean refreshConsentRememberFor, int consentRememberFor) {
        this.session = new Session(new IdToken(givenName, familyName, birthDate, sessionId), refreshRememberFor, rememberFor, refreshConsentRememberFor, consentRememberFor);
    }

    @Data
    @AllArgsConstructor
    @JsonNaming(SnakeCaseStrategy.class)
    public static final class Session {
        private IdToken idToken;
        private boolean refreshRememberFor;
        private int rememberFor;
        private boolean refreshConsentRememberFor;
        private int consentRememberFor;
    }

    @Data
    @AllArgsConstructor
    @JsonNaming(SnakeCaseStrategy.class)
    public static final class IdToken {
        private String givenName;
        private String familyName;
        private String birthdate;
        private String sid;
    }
}
