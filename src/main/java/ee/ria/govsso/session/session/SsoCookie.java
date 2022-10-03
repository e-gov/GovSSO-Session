package ee.ria.govsso.session.session;

import lombok.Builder;
import lombok.Value;
import lombok.With;

import static org.springframework.util.Assert.hasText;

@Value
@Builder
public class SsoCookie {

    public static final String COOKIE_NAME_GOVSSO = "__Host-AUTH";
    public static final String COOKIE_VALUE_LOGIN_CHALLENGE = "login_challenge";
    public static final String COOKIE_VALUE_TARA_STATE = "tara_state";
    public static final String COOKIE_VALUE_TARA_NONCE = "tara_nonce";

    String loginChallenge;
    @With
    String taraAuthenticationRequestState;
    @With
    String taraAuthenticationRequestNonce;

    public SsoCookie(String loginChallenge, String taraAuthenticationRequestState, String taraAuthenticationRequestNonce) {
        hasText(loginChallenge, "Session login request info challenge must not be blank");
        this.loginChallenge = loginChallenge;
        this.taraAuthenticationRequestState = taraAuthenticationRequestState;
        this.taraAuthenticationRequestNonce = taraAuthenticationRequestNonce;
    }
}
