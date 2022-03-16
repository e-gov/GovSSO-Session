package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

import java.net.URI;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LogoutRequestInfo {

    private String challenge;
    private Client client;
    private String subject;
    @JsonProperty("sid")
    private String sessionId;
    // TODO: for some reason Hydra does not return full URL here, so have to use URI instead of URL.
    private URI requestUrl;
    private Boolean rpInitiated;
}
