package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

import java.util.List;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class ConsentAcceptRequest {

    private ConsentAcceptRequest.LoginSession session;
    private List<String> grantScope;
    private boolean remember;
    private int rememberFor;
    private List<String> grantAccessTokenAudience;

    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class LoginSession {
        private ConsentAcceptRequest.IdToken idToken;
        private ConsentAcceptRequest.AccessToken accessToken;
    }

    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class IdToken {
        private String givenName;
        private String familyName;
        private String birthdate;
        private String phoneNumber;
        private Boolean phoneNumberVerified;
    }

    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class AccessToken {
        private String acr;
        private String[] amr;
        private String givenName;
        private String familyName;
        private String birthdate;
        private String phoneNumber;
        private Boolean phoneNumberVerified;
    }
}
