package ee.ria.govsso.session.service.hydra;

import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.util.List;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Metadata {
    private OidcClient oidcClient = new OidcClient();
    private boolean displayUserConsent;
    private List<String> skipUserConsentClientIds;
    private String paasukeParameters;
    private String minimumAcrValue;
    private ClientType clientType;
}
