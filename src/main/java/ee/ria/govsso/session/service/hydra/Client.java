package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

import java.util.List;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Client {

    private String clientId;
    private String clientName;
    private Metadata metadata;
    private String accessTokenStrategy;
    private List<String> audience;

    @JsonIgnore
    public boolean isSecuredApp() {
        return metadata.getClientType() == ClientType.SECURED_APP;
    }

}
