package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;
import lombok.Data;

import java.time.Instant;
import java.util.List;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LoginAcceptRequest {

    boolean remember;
    String acr;
    String subject;
    Context context;
    int rememberFor;
    List<String> amr;
    boolean extendSessionLifespan;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    Instant authenticatedAt;

}
