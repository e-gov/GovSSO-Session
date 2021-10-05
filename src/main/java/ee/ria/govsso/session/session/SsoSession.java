package ee.ria.govsso.session.session;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class SsoSession {

    public static final String SSO_SESSION = "sso.session";

    private LoginRequestInfo loginRequestInfo;

    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class LoginRequestInfo {
        //Models selected fields of https://www.ory.sh/hydra/docs/reference/api/#operation/getLoginRequest, Ory Hydra response is deserialized into this class.

        private String challenge;
        private Client client;
    }

    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class Client {

        private String[] redirectUris;
    }
}
