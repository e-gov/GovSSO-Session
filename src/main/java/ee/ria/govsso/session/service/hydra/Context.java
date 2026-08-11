package ee.ria.govsso.session.service.hydra;

import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Context {

    private String taraIdToken;
    private String ipAddress;
    private String userAgent;
    private String ipCountry;
    // TODO Remove after fully migrating to SessionType
    private boolean isLongLivingSession;
    private SessionType sessionType;
    private String authHandoverToken;
}
