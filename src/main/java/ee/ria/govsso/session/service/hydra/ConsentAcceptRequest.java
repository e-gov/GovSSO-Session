package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonInclude;
import ee.ria.govsso.session.token.AccessTokenClaims;
import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

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
        private AccessTokenClaims accessToken;
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
        private RepresenteeList representeeList;
        private ClientType initiator;
    }
}
