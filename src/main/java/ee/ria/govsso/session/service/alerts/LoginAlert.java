package ee.ria.govsso.session.service.alerts;

import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.util.List;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LoginAlert {
    private boolean enabled;
    private List<MessageTemplate> messageTemplates;
}
