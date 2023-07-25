package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
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
