package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class ConsentRequestInfo {

    //Models selected fields of https://www.ory.sh/docs/hydra/reference/api#tag/oAuth2/operation/getOAuth2ConsentRequest, Ory Hydra response is deserialized into this class.

    private String challenge;
    private String loginChallenge;
    private String loginSessionId;
    private String[] requestedScope;
    private Client client;
    private Context context;
    private OidcContext oidcContext;
    private OffsetDateTime requestedAt;
    private String[] requestedAccessTokenAudience;
}
