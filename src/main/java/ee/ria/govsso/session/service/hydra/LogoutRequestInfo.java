package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LogoutRequestInfo {

    private String challenge;
    private Client client;
    private String subject;
    @JsonProperty("sid")
    private String sessionId;
    private String requestUrl;
    private Boolean rpInitiated;
}
