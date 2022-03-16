package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Value;

@Value
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LoginRejectRequest {

    String error = "user_cancel";
    String errorDebug = "User canceled the authentication process.";
    String errorDescription = "User canceled the authentication process.";
}
