package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.session.SsoSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class LoginReauthenticateController {
    public static final String LOGIN_REAUTHENTICATE_REQUEST_MAPPING = "/login/reauthenticate";
    private final HydraService hydraService;

    @PostMapping(value = LOGIN_REAUTHENTICATE_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView loginReauthenticate(@SessionAttribute(value = SSO_SESSION) SsoSession ssoSession, HttpServletRequest request, HttpServletResponse response) {

        if (ssoSession.getLoginChallenge() == null) {
            throw new SsoException(ErrorCode.USER_INPUT_OR_EXPIRED, "Login challenge was not found in SSO session.");
        }

        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(ssoSession.getLoginChallenge());

        if (loginRequestInfo.getSubject().isEmpty())
            throw new SsoException(ErrorCode.USER_INPUT, "Hydra login request subject must not be empty.");

        hydraService.deleteConsent(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
        hydraService.deleteLogin(loginRequestInfo.getSessionId());
        hydraService.rejectLogin(loginRequestInfo.getChallenge());

        deleteHydraSessionCookie(request, response);

        return new RedirectView(loginRequestInfo.getRequestUrl());
    }

    // For this to work, it is expected to run Hydra and GOVSSO-Session behind a reverse proxy that exposes them under the same domain. Only then will cookies set by Hydra also reach GOVSSO-Session.
    private void deleteHydraSessionCookie(HttpServletRequest request, HttpServletResponse response) {
        String cookieName = request.isSecure() ? "oauth2_authentication_session" : "oauth2_authentication_session_insecure";

        for (Cookie cookie : request.getCookies()) {
            if (cookie.getName().equals(cookieName)) {
                Cookie newCookie = createCookie(cookieName, cookie.getValue());
                response.addCookie(newCookie);
            }
        }
    }

    private Cookie createCookie(String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        return cookie;
    }

}
