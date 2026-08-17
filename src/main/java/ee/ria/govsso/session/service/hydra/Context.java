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

    // TODO Temporary solution. Remove after all sessions created before session type was added to context have
    //  expired, and instead throw when session type is missing.
    public SessionType getSessionTypeOrFallback() {
        SessionType sessionType = this.getSessionType();
        if (sessionType != null) {
            return sessionType;
        }
        return this.isLongLivingSession() ? SessionType.SECURED_APP_SESSION : SessionType.WEB_SESSION;
    }
}
