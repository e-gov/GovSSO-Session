package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonIgnore;
import ee.ria.govsso.session.token.UserAttributes;
import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;


@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Context {

    private String ipAddress;
    private String userAgent;
    private String ipCountry;
    private SessionType sessionType;
    private UserAttributes userAttributes;

    @JsonIgnore
    public ClientType getInitiator() {
        return switch (this.getSessionType()) {
            case SECURED_APP_SESSION, SECURED_APP_WEB_SESSION -> ClientType.SECURED_APP;
            case WEB_SESSION -> ClientType.DEFAULT;
        };
    }
}
