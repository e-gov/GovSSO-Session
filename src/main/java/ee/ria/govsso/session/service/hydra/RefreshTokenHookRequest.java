package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.databind.PropertyNamingStrategies.SnakeCaseStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

import java.util.List;

@Data
@JsonNaming(SnakeCaseStrategy.class)
public final class RefreshTokenHookRequest {
    private String subject;
    private String clientId;
    private List<String> grantedScopes;
    private List<String> grantedAudience;
    private Session session;
    private Requester requester;

    public String getSessionId() {
        return session.getIdToken().getIdTokenClaims().getExt().getSid();
    }

    @Data
    @JsonNaming(SnakeCaseStrategy.class)
    public static final class Session {
        private IdToken idToken;
    }

    @Data
    @JsonNaming(SnakeCaseStrategy.class)
    public static final class IdToken {
        private IdTokenClaims idTokenClaims;
    }

    @Data
    @JsonNaming(SnakeCaseStrategy.class)
    public static final class IdTokenClaims {
        private String acr;
        private Ext ext;
    }

    @Data
    @JsonNaming(SnakeCaseStrategy.class)
    public static final class Ext {
        private String givenName;
        private String familyName;
        private String birthdate;
        private String sid;
    }

    @Data
    @JsonNaming(SnakeCaseStrategy.class)
    public static final class Requester {
        private String clientId;
        private List<String> grantedScopes;
        private List<String> grantedAudience;
        private List<String> grantTypes;
    }
}
