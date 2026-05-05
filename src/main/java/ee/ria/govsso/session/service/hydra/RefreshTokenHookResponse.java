package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonInclude;
import ee.ria.govsso.session.token.AccessTokenClaims;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import tools.jackson.databind.PropertyNamingStrategies.SnakeCaseStrategy;
import tools.jackson.databind.annotation.JsonNaming;

@Data
@JsonNaming(SnakeCaseStrategy.class)
public final class RefreshTokenHookResponse {
    private Session session;

    @Builder
    public RefreshTokenHookResponse(IdToken idToken, AccessTokenClaims accessToken, boolean refreshRememberFor, int rememberFor, boolean refreshConsentRememberFor, int consentRememberFor) {
        this.session = new Session(idToken, accessToken, refreshRememberFor, rememberFor, refreshConsentRememberFor, consentRememberFor);
    }

    @Data
    @AllArgsConstructor
    @JsonNaming(SnakeCaseStrategy.class)
    public static final class Session {
        private IdToken idToken;
        private AccessTokenClaims accessToken;
        private boolean refreshRememberFor;
        private int rememberFor;
        private boolean refreshConsentRememberFor;
        private int consentRememberFor;
    }

    @Builder
    @Getter
    @JsonNaming(SnakeCaseStrategy.class)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class IdToken {
        private String givenName;
        private String familyName;
        private String birthdate;
        private String sid;
        private String phoneNumber;
        private Boolean phoneNumberVerified;
        private Representee representee;
        private RepresenteeList representeeList;
        private ClientType initiator;
    }
}
