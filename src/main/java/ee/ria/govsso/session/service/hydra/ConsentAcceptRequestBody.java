package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

import java.util.List;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class ConsentAcceptRequestBody {

    private ConsentAcceptRequestBody.LoginSession session;
    private List<String> grantScope;
    private boolean remember;
    private int rememberFor;

    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class LoginSession {
        private ConsentAcceptRequestBody.IdToken idToken;
    }

    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class IdToken {
        private ConsentAcceptRequestBody.ProfileAttributes profileAttributes;
    }

    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class ProfileAttributes {
        private String familyName;
        private String givenName;
        private String dateOfBirth;
    }
}
