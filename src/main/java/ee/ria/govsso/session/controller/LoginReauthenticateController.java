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

import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class LoginReauthenticateController {
    public static final String LOGIN_REAUTHENTICATE_REQUEST_MAPPING = "/login/reauthenticate";
    private final HydraService hydraService;

    @PostMapping(value = LOGIN_REAUTHENTICATE_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView loginReauthenticate(@SessionAttribute(value = SSO_SESSION) SsoSession ssoSession) {

        if (ssoSession.getLoginChallenge() == null) {
            throw new SsoException(ErrorCode.USER_INPUT_OR_EXPIRED, "Login challenge was not found in SSO session.");
        }

        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(ssoSession.getLoginChallenge());

        if (loginRequestInfo.getSubject().isEmpty())
            throw new SsoException(ErrorCode.USER_INPUT, "Hydra login request subject must not be empty.");

        hydraService.deleteConsent(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
        hydraService.deleteLogin(loginRequestInfo.getSessionId());
        hydraService.rejectLogin(loginRequestInfo.getChallenge());

        return new RedirectView(loginRequestInfo.getRequestUrl());
    }

}
