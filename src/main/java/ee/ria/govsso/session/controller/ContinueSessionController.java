package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.common.ClientRequestMetadata;
import ee.ria.govsso.session.common.ClientRequestMetadataFactory;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.StatisticsLogger;
import ee.ria.govsso.session.service.hydra.Consent;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LevelOfAssurance;
import ee.ria.govsso.session.service.hydra.LoginAcceptResponse;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.hydra.OidcContext;
import ee.ria.govsso.session.service.hydra.Prompt;
import ee.ria.govsso.session.service.hydra.SessionToken;
import ee.ria.govsso.session.service.hydra.SessionType;
import ee.ria.govsso.session.token.UserAttributes;
import ee.ria.govsso.session.util.CookieUtil;
import ee.ria.govsso.session.util.LoginRequestInfoUtil;
import ee.ria.govsso.session.util.PromptUtil;
import ee.ria.govsso.session.util.RequestUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.servlet.view.RedirectView;

import java.util.List;

import static ee.ria.govsso.session.error.ErrorCode.TECHNICAL_GENERAL;
import static ee.ria.govsso.session.error.ErrorCode.USER_INPUT;
import static ee.ria.govsso.session.logging.StatisticsLogger.AUTHENTICATION_REQUEST_TYPE;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.CONTINUE_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.LOGIN_REQUEST_INFO;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class ContinueSessionController {
    public static final String AUTH_VIEW_REQUEST_MAPPING = "/login/continuesession";

    private final HydraService hydraService;
    private final StatisticsLogger statisticsLogger;
    private final ClientRequestMetadataFactory clientRequestMetadataFactory;

    @PostMapping(value = AUTH_VIEW_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView continueSession(
            @ModelAttribute("loginChallenge")
            @Pattern(regexp = "^[a-f0-9]{32}$", message = "Incorrect login_challenge format") String loginChallenge,
            @RequestHeader(value = HttpHeaders.USER_AGENT, required = false) String userAgent,
            HttpServletRequest request) {

        RequestUtil.setFlowTraceId(loginChallenge);
        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(loginChallenge);
        request.setAttribute(LOGIN_REQUEST_INFO, loginRequestInfo);
        request.setAttribute(AUTHENTICATION_REQUEST_TYPE, CONTINUE_SESSION);

        if (!CookieUtil.isValidHydraSessionCookie(request, loginRequestInfo.getSessionId())) {
            throw new SsoException(USER_INPUT, "Unable to continue session! Oidc session cookie not found.");
        }

        validateLoginRequestInfo(loginRequestInfo);
        if (loginRequestInfo.getClient().isSecuredApp()) {
            throw new SsoException(USER_INPUT, "SECURED_APP client type is not allowed to continue an existing session.");
        }
        List<Consent> consents = hydraService.getValidConsentsAtRequestTime(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId(), loginRequestInfo.getRequestedAt());
        SessionToken sessionToken = hydraService.getSessionTokenFromConsentContext(consents);
        if (sessionToken == null) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "No valid consent requests found");
        }
        if (sessionToken.sessionType() == SessionType.SECURED_APP_SESSION) {
            throw new SsoException(USER_INPUT, "Secured app sessions are not allowed to be continued");
        }

        ClientRequestMetadata metadata = clientRequestMetadataFactory.fromRequest(request);
        validateAcr(loginRequestInfo, sessionToken.userAttributes());
        return acceptLogin(loginRequestInfo, sessionToken, metadata);
    }

    private void validateLoginRequestInfo(LoginRequestInfo loginRequestInfo) {
        OidcContext oidcContext = loginRequestInfo.getOidcContext();

        if (loginRequestInfo.getSubject().isEmpty()) {
            throw new SsoException(ErrorCode.USER_INPUT, "Login request subject must not be empty");
        }
        if (!loginRequestInfo.isSkip()) {
            throw new SsoException(TECHNICAL_GENERAL, "Subject exists, therefore login response skip value can not be false");
        }

        LoginRequestInfoUtil.validateScopes(loginRequestInfo);
        loginRequestInfo.validateAcr();

        Prompt prompt = PromptUtil.getAndValidatePromptFromRequestUrl(loginRequestInfo.getRequestUrl());
        if (prompt != Prompt.CONSENT) {
            throw new SsoException(ErrorCode.USER_INPUT, "Request URL must contain prompt=consent");
        }
        if (oidcContext != null && oidcContext.getIdTokenHintClaims() != null) {
            throw new SsoException(ErrorCode.USER_INPUT, "Login request ID token hint claim must be null");
        }
    }

    private void validateAcr(LoginRequestInfo loginRequestInfo, UserAttributes userAttributes) {
        LevelOfAssurance requestAcr = loginRequestInfo.getAcr();
        LevelOfAssurance requiredAcr = requestAcr != null ? requestAcr : LevelOfAssurance.DEFAULT;
        LevelOfAssurance sessionAcr = LevelOfAssurance.findByAcrName(userAttributes.acr());
        if (sessionAcr.getAcrLevel() < requiredAcr.getAcrLevel()) {
            throw new SsoException(TECHNICAL_GENERAL, "Session acr value must be equal to or higher than hydra login request acr");
        }
    }

    private RedirectView acceptLogin(LoginRequestInfo loginRequestInfo, SessionToken sessionToken, ClientRequestMetadata metadata) {
        LoginAcceptResponse response = hydraService.acceptSessionContinuation(sessionToken, loginRequestInfo, metadata);
        statisticsLogger.logAccept(CONTINUE_SESSION, sessionToken.userAttributes(), loginRequestInfo);
        return new RedirectView(response.getRedirectTo().toString());
    }
}
