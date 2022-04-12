package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.Consent;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LogoutAcceptResponseBody;
import ee.ria.govsso.session.service.hydra.LogoutRequestInfo;
import ee.ria.govsso.session.util.LocaleUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import javax.validation.constraints.Pattern;
import java.util.List;
import java.util.Optional;

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
                                   @Pattern(regexp = REGEXP_LOGOUT_CHALLENGE) String logoutChallenge,
                                   @CookieValue(value = "__Host-LOCALE", required = false) String localeCookie,
                                   @RequestParam(name = "lang", required = false) String language) {

        LogoutRequestInfo logoutRequestInfo = hydraService.fetchLogoutRequestInfo(logoutChallenge);

        // Set locale as early as possible, so it could be used by error messages as much as possible.
        if (language == null && localeCookie == null) {
            LocaleUtil.setLocale(logoutRequestInfo);
        }

        validateLogoutRequestInfo(logoutRequestInfo);

        String subject = logoutRequestInfo.getSubject();
        String sessionId = logoutRequestInfo.getSessionId();
        String requestClientId = logoutRequestInfo.getClient().getClientId();
        List<Consent> consents = hydraService.getConsents(subject, sessionId);

        if (consents.isEmpty() || consentExistsOnlyForRequestClient(consents, requestClientId)) {
            LogoutAcceptResponseBody logoutAcceptResponse = hydraService.acceptLogout(logoutChallenge);
            return new ModelAndView("redirect:" + logoutAcceptResponse.getRedirectTo());
        }

        Optional<Consent> clientConsent = consents.stream()
                .filter(c -> c.getConsentRequest().getClient().getClientId().equals(requestClientId))
                .findFirst();
        if (clientConsent.isPresent()) {
            hydraService.deleteConsentByClientSession(requestClientId, subject, sessionId);
        }
        return getLogoutView(logoutRequestInfo, consents);
    }

    @PostMapping(value = LOGOUT_END_SESSION_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView endSession(@ModelAttribute("logoutChallenge")
                                   @Pattern(regexp = REGEXP_LOGOUT_CHALLENGE) String logoutChallenge) {

        LogoutRequestInfo logoutRequestInfo = hydraService.fetchLogoutRequestInfo(logoutChallenge);
        validateLogoutRequestInfo(logoutRequestInfo);

        LogoutAcceptResponseBody logoutAcceptResponse = hydraService.acceptLogout(logoutChallenge);
        return new RedirectView(logoutAcceptResponse.getRedirectTo());
    }

    @PostMapping(value = LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView continueSession(@ModelAttribute("logoutChallenge")
                                        @Pattern(regexp = REGEXP_LOGOUT_CHALLENGE) String logoutChallenge) {

        LogoutRequestInfo logoutRequestInfo = hydraService.fetchLogoutRequestInfo(logoutChallenge);
        validateLogoutRequestInfo(logoutRequestInfo);

        hydraService.rejectLogout(logoutChallenge);
        String postLogoutRedirectUri = getPostLogoutRedirectUriFromRequestUrl(logoutRequestInfo.getRequestUrl());
        return new RedirectView(postLogoutRedirectUri);
    }

    private void validateLogoutRequestInfo(LogoutRequestInfo logoutRequestInfo) {
        if (!logoutRequestInfo.getRpInitiated()) {
            throw new SsoException(ErrorCode.USER_INPUT, "Logout not initiated by relying party");
        }

        String postLogoutRedirectUri = getPostLogoutRedirectUriFromRequestUrl(logoutRequestInfo.getRequestUrl());
        if (StringUtils.isBlank(postLogoutRedirectUri)) {
            throw new SsoException(ErrorCode.USER_INPUT, "Invalid post logout redirect URI");
        }
    }

    private String getPostLogoutRedirectUriFromRequestUrl(String requestUrl) {
        return UriComponentsBuilder.fromUriString(requestUrl)
                .build()
                .getQueryParams()
                .getFirst("post_logout_redirect_uri");
    }

    private boolean consentExistsOnlyForRequestClient(List<Consent> consents, String requestClientId) {
        if (consents.size() == 1) {
            String consentClientId = consents.get(0).getConsentRequest().getClient().getClientId();
            return consentClientId.equals(requestClientId);
        }
        return false;
    }

    private ModelAndView getLogoutView(LogoutRequestInfo logoutRequestInfo, List<Consent> consents) {
        String logoutChallenge = logoutRequestInfo.getChallenge();
        String clientId = logoutRequestInfo.getClient().getClientId();
        String clientName = LocaleUtil.getTranslatedClientName(logoutRequestInfo.getClient());

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
        logoutView.addObject("logo", logoutRequestInfo.getClient().getMetadata().getOidcClient().getLogo());
        return logoutView;
    }
}
