package ee.ria.govsso.session.service.hydra;

import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class OidcContext {

    private List<String> acrValues;
    private Map<String, Object> idTokenHintClaims;
    private List<String> uiLocales = new ArrayList<>();
}
