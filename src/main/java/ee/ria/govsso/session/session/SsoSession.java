package ee.ria.govsso.session.session;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.io.Serializable;

@Data
@RequiredArgsConstructor
public class SsoSession implements Serializable {

    public static final String SSO_SESSION = "sso.session";

    private LoginRequestInfo loginRequestInfo;

    @Data
    public static class LoginRequestInfo implements Serializable {
        @JsonProperty("challenge")
        private String challenge;
    }

}
