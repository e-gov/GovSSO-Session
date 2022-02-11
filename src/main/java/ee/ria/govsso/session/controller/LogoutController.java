package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.Consent;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LogoutAcceptResponseBody;
import ee.ria.govsso.session.service.hydra.LogoutRequestInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import javax.validation.constraints.Pattern;
import java.util.List;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class LogoutController {
    public static final String LOGOUT_INIT_REQUEST_MAPPING = "/logout/init";
    public static final String LOGOUT_END_SESSION_REQUEST_MAPPING = "/logout/endsession";
    public static final String LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING = "/logout/continuesession";
    public static final String REGEXP_LOGOUT_CHALLENGE = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
    private final HydraService hydraService;

    @GetMapping(value = LOGOUT_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView logoutInit(@RequestParam(name = "logout_challenge")
                                   @Pattern(regexp = REGEXP_LOGOUT_CHALLENGE) String logoutChallenge) {

        LogoutRequestInfo logoutRequestInfo = hydraService.fetchLogoutRequestInfo(logoutChallenge);

        if (logoutRequestInfo.getRpInitiated()) {
            List<Consent> consents = hydraService.getConsents(logoutRequestInfo.getSubject(), logoutRequestInfo.getSessionId());

            boolean isValidForAutoLogout = consents.size() == 1;
            if (isValidForAutoLogout) {
                LogoutAcceptResponseBody logoutAcceptResponse = hydraService.acceptLogout(logoutChallenge);
                return new ModelAndView("redirect:" + logoutAcceptResponse.getRedirectTo());
            } else {
                hydraService.deleteConsentByClientSession(logoutRequestInfo.getClient().getClientId(),
                        logoutRequestInfo.getSubject(), logoutRequestInfo.getSessionId());
                return getLogoutView(logoutRequestInfo, consents);
            }
        } else {
            throw new SsoException(ErrorCode.USER_INPUT, "Logout not initiated by relying party");
        }
    }

    @PostMapping(value = LOGOUT_END_SESSION_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView endSession(@ModelAttribute("logoutChallenge")
                                   @Pattern(regexp = REGEXP_LOGOUT_CHALLENGE) String logoutChallenge) {

        LogoutAcceptResponseBody logoutAcceptResponse = hydraService.acceptLogout(logoutChallenge);
        return new RedirectView(logoutAcceptResponse.getRedirectTo());
    }

    @PostMapping(value = LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView continueSession(@ModelAttribute("logoutChallenge")
                                        @Pattern(regexp = REGEXP_LOGOUT_CHALLENGE) String logoutChallenge) {

        LogoutRequestInfo logoutRequestInfo = hydraService.fetchLogoutRequestInfo(logoutChallenge);
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(logoutRequestInfo.getRequestUrl());
        String postLogoutRedirectUri = builder.build().getQueryParams().getFirst("post_logout_redirect_uri");
        if (postLogoutRedirectUri == null || postLogoutRedirectUri.isBlank()) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Invalid post logout redirect URI");
        }

        hydraService.rejectLogout(logoutChallenge);
        return new RedirectView(postLogoutRedirectUri);
    }

    private ModelAndView getLogoutView(LogoutRequestInfo logoutRequestInfo, List<Consent> consents) {
        String logoutChallenge = logoutRequestInfo.getChallenge();
        String clientId = logoutRequestInfo.getClient().getClientId();
        String clientName = logoutRequestInfo.getClient().getClientName();

        List<String> activeSessions = consents.stream()
                .map(c -> c.getConsentRequest().getClient())
                .filter(c -> !c.getClientId().equals(clientId))
                .map(Client::getClientName)
                .sorted()
                .distinct()
                .toList();

        ModelAndView logoutView = new ModelAndView("logoutView");
        logoutView.addObject("logoutChallenge", logoutChallenge);
        logoutView.addObject("clientName", clientName);
        logoutView.addObject("activeSessions", activeSessions);
        return logoutView;
    }
}
