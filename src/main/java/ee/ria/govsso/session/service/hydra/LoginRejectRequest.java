package ee.ria.govsso.session.service.hydra;

import lombok.Value;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

@Value
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LoginRejectRequest {

    String error = "user_cancel";
    String errorDebug = "User canceled the authentication process.";
    String errorDescription = "User canceled the authentication process.";
}
