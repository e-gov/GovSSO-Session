package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

import java.util.List;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Metadata {
    private OidcClient oidcClient = new OidcClient();
    private boolean displayUserConsent;
    private List<String> skipUserConsentClientIds;
}
