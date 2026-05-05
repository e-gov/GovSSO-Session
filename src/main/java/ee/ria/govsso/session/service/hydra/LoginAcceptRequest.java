package ee.ria.govsso.session.service.hydra;

import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;
import lombok.Data;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LoginAcceptRequest {

    boolean remember;
    String acr;
    String subject;
    Context context;
    int rememberFor;
    String[] amr;
    boolean extendSessionLifespan;

}
