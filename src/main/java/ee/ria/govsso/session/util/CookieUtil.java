package ee.ria.govsso.session.util;

import com.nimbusds.jose.util.Base64;
import lombok.experimental.UtilityClass;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Arrays;


@UtilityClass
public class CookieUtil {

    private static final String HYDRA_SESSION_COOKIE_NAME = "__Host-ory_hydra_session";

    /**
     * For this to work, it is expected to run Hydra and GOVSSO-Session behind a reverse proxy that exposes them under
     * the same domain. Only then will cookies set by Hydra also reach GOVSSO-Session.
     *
     * @param request
     * @param response
     */
    public void deleteHydraSessionCookie(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(HYDRA_SESSION_COOKIE_NAME)) {
                    Cookie newCookie = createCookie(HYDRA_SESSION_COOKIE_NAME, cookie.getValue());
                    response.addCookie(newCookie);
                }
            }
        }
    }

    /**
     * For this to work, it is expected to run Hydra and GOVSSO-Session behind a reverse proxy that exposes them under
     * the same domain. Only then will cookies set by Hydra also reach GOVSSO-Session.
     *
     * @param request
     * @param sessionId
     */
    public boolean isValidHydraSessionCookie(HttpServletRequest request, String sessionId) {
        Cookie[] cookies = request.getCookies();
        return cookies != null && Arrays.stream(cookies)
                .filter(c -> c.getName().equals(HYDRA_SESSION_COOKIE_NAME))
                .anyMatch(c -> containsSessionId(c.getValue(), sessionId));
    }

    /**
     * Decoded cookie value middle part is in <a href="https://pkg.go.dev/encoding/gob">golang gob</a> format and
     * session id value is searched without decoding. The third part of the decoded cookie value may sometimes contain
     * a "|" character and cause the decodedParts length to be larger than 3.
     */
    boolean containsSessionId(String cookieValue, String sessionId) {
        if (cookieValue == null) {
            return false;
        }
        String[] decodedParts = Base64.from(cookieValue).decodeToString().split("\\|");
        return decodedParts.length >= 3 && Base64.from(decodedParts[1]).decodeToString().contains(sessionId);
    }

    private Cookie createCookie(String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        return cookie;
    }
}
