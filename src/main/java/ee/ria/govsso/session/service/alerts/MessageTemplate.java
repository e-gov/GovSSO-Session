package ee.ria.govsso.session.service.alerts;

import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class MessageTemplate {
    private String message;
    private String locale;
}
