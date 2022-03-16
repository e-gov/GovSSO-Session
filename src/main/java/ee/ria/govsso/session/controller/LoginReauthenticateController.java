package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.util.CookieUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.Pattern;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class LoginReauthenticateController {
    public static final String LOGIN_REAUTHENTICATE_REQUEST_MAPPING = "/login/reauthenticate";
    private final HydraService hydraService;

    @PostMapping(value = LOGIN_REAUTHENTICATE_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView loginReauthenticate(@ModelAttribute("loginChallenge")
                                            @Pattern(regexp = "^[a-f0-9]{32}$", message = "Incorrect login_challenge format") String loginChallenge,
                                            HttpServletRequest request,
                                            HttpServletResponse response) {

        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(loginChallenge);
        if (loginRequestInfo.getSubject().isEmpty()) {
            throw new SsoException(ErrorCode.USER_INPUT, "Hydra login request subject must not be empty.");
        }

        hydraService.deleteConsentBySubjectSession(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
        hydraService.deleteLoginSessionAndRelatedLoginRequests(loginRequestInfo.getSessionId());
        CookieUtil.deleteHydraSessionCookie(request, response);
        return new RedirectView(loginRequestInfo.getRequestUrl().toString());
    }
}
