package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.time.Duration;
import java.util.List;

import static java.util.Objects.requireNonNullElse;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Metadata {
    private OidcClient oidcClient = new OidcClient();
    private boolean displayUserConsent;
    private List<String> skipUserConsentClientIds;
    private String paasukeParameters;
    private String minimumAcrValue;
    private ClientType clientType;
    private Boolean allowSecuredAppWebSession;
    private String securedAppSessionMaxDuration;

    public boolean getAllowSecuredAppWebSession() {
        return requireNonNullElse(allowSecuredAppWebSession, false);
    }

    @JsonIgnore
    public Duration getSecuredAppSessionMaxAge() {
        if (!getAllowSecuredAppWebSession()) {
            throw new IllegalStateException(
                    "Client must allow %s sessions".formatted(SessionType.SECURED_APP_WEB_SESSION));
        }
        if (securedAppSessionMaxDuration == null) {
            return null;
        }
        return HydraDurationFormat.parse(securedAppSessionMaxDuration);
    }

}
