package ee.ria.govsso.session.service.alerts;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

import java.util.List;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LoginAlert {
    private boolean enabled;
    private List<MessageTemplate> messageTemplates;
}
