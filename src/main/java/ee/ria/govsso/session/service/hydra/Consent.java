package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Consent {
    private OffsetDateTime requestedAt;
    private Integer rememberFor;
    private ConsentRequestInfo consentRequest;

}
