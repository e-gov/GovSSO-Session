package ee.ria.govsso.session.session;

import lombok.Data;

@Data
public class SsoSession {

    public static final String SSO_SESSION = "sso.session";

    private String loginChallenge;
    private String taraAuthenticationRequestNonce;
    private String taraAuthenticationRequestState;
}
