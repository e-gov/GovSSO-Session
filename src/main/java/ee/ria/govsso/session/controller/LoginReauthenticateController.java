package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.StatisticsLogger;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.util.CookieUtil;
import ee.ria.govsso.session.util.RequestUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.view.RedirectView;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.Pattern;

import static ee.ria.govsso.session.logging.StatisticsLogger.AUTHENTICATION_REQUEST_TYPE;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.CONTINUE_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.LOGIN_REQUEST_INFO;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class LoginReauthenticateController {

    public static final String LOGIN_REAUTHENTICATE_REQUEST_MAPPING = "/login/reauthenticate";
    private final HydraService hydraService;
    private final StatisticsLogger statisticsLogger;

    @PostMapping(value = LOGIN_REAUTHENTICATE_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView loginReauthenticate(@ModelAttribute("loginChallenge")
                                            @Pattern(regexp = "^[a-f0-9]{32}$", message = "Incorrect login_challenge format") String loginChallenge,
                                            HttpServletRequest request,
                                            HttpServletResponse response) {

        RequestUtil.setFlowTraceId(loginChallenge);
        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(loginChallenge);
        request.setAttribute(LOGIN_REQUEST_INFO, loginRequestInfo);
        request.setAttribute(AUTHENTICATION_REQUEST_TYPE, CONTINUE_SESSION);

        if (loginRequestInfo.getSubject().isEmpty()) {
            throw new SsoException(ErrorCode.USER_INPUT, "Hydra login request subject must not be empty.");
        }

        hydraService.deleteConsentBySubjectSession(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
        hydraService.deleteLoginSessionAndRelatedLoginRequests(loginRequestInfo.getSessionId());

        statisticsLogger.logReject(loginRequestInfo, CONTINUE_SESSION);
        CookieUtil.deleteHydraSessionCookie(request, response);
        return new RedirectView(loginRequestInfo.getRequestUrl().toString());
    }
}
