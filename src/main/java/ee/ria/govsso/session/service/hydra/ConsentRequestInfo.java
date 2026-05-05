package ee.ria.govsso.session.service.hydra;

import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.time.OffsetDateTime;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class ConsentRequestInfo {

    //Models selected fields of https://www.ory.sh/docs/hydra/reference/api#tag/oAuth2/operation/getOAuth2ConsentRequest, Ory Hydra response is deserialized into this class.

    private String challenge;
    private String loginChallenge;
    private String loginSessionId;
    private String subject;
    private String[] requestedScope;
    private Client client;
    private Context context;
    private OidcContext oidcContext;
    private OffsetDateTime requestedAt;
    private OffsetDateTime authenticatedAt;
    private String[] requestedAccessTokenAudience;
}
