package ee.ria.govsso.session.service.hydra;

import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.net.URL;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LogoutAcceptResponse {

    private URL redirectTo;
}
