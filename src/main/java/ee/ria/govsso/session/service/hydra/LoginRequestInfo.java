package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

import java.net.URL;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LoginRequestInfo {
    //Models selected fields of https://www.ory.sh/hydra/docs/reference/api/#operation/getLoginRequest, Ory Hydra response is deserialized into this class.

    private String challenge;
    private Client client;
    private String subject;
    private String sessionId;
    private URL requestUrl;
    private String[] requestedScope;
    private OidcContext oidcContext;
    private boolean skip;
}
