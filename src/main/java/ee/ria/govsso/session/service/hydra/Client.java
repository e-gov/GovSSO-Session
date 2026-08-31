package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.time.Duration;
import java.util.List;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Client {

    private String clientId;
    private String clientName;
    private Metadata metadata;
    private String accessTokenStrategy;
    private List<String> audience;
    private String authorizationCodeGrantRefreshTokenLifespan;
    private String scope;

    @JsonIgnore
    public boolean isSecuredApp() {
        return metadata.getClientType() == ClientType.SECURED_APP;
    }

    @JsonIgnore
    public Duration getLongLivedSessionLifetime() {
        if (!isSecuredApp()) {
            throw new IllegalStateException("Client must be marked as \"%s\"".formatted(ClientType.SECURED_APP));
        }
        return HydraDurationFormat.parse(authorizationCodeGrantRefreshTokenLifespan);
    }

}
