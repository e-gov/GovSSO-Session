package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import ee.ria.govsso.session.common.ClientRequestMetadata;
import ee.ria.govsso.session.common.ClientRequestMetadataFactory;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.StatisticsLogger;
import ee.ria.govsso.session.service.alerts.AlertsService;
import ee.ria.govsso.session.service.hydra.ClientType;
import ee.ria.govsso.session.service.hydra.Consent;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LevelOfAssurance;
import ee.ria.govsso.session.service.hydra.LoginAcceptResponse;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.hydra.Metadata;
import ee.ria.govsso.session.service.hydra.OidcContext;
import ee.ria.govsso.session.service.hydra.Prompt;
import ee.ria.govsso.session.service.tara.TaraService;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieSigner;
import ee.ria.govsso.session.token.AuthHandoverTokenVerifier;
import ee.ria.govsso.session.token.UserAttributes;
import ee.ria.govsso.session.token.UserAttributesFactory;
import ee.ria.govsso.session.util.AuthHandoverTokenUtil;
import ee.ria.govsso.session.util.CookieUtil;
import ee.ria.govsso.session.util.LocaleUtil;
import ee.ria.govsso.session.util.LoginRequestInfoUtil;
import ee.ria.govsso.session.util.ModelUtil;
import ee.ria.govsso.session.util.RequestUtil;
import ee.ria.govsso.session.util.SecureAppUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.HtmlUtils;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Clock;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;

import static ee.ria.govsso.session.error.ErrorCode.TECHNICAL_GENERAL;
import static ee.ria.govsso.session.error.ErrorCode.USER_INPUT;
import static ee.ria.govsso.session.logging.StatisticsLogger.AUTHENTICATION_REQUEST_TYPE;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.AUTH_HANDOVER;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.CONTINUE_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.START_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.LOGIN_REQUEST_INFO;
import static ee.ria.govsso.session.service.helper.ClientScopes.SCOPE_PHONE;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class LoginInitController {

    public static final String LOGIN_INIT_REQUEST_MAPPING = "/login/init";

    private final SsoCookieSigner ssoCookieSigner;
    private final HydraService hydraService;
    private final TaraService taraService;
    private final StatisticsLogger statisticsLogger;
    private final SsoConfigurationProperties ssoConfigurationProperties;
    private final ClientRequestMetadataFactory clientRequestMetadataFactory;
    private final AuthHandoverTokenVerifier authHandoverTokenVerifier;
    private final UserAttributesFactory userAttributesFactory;
    @Autowired(required = false)
    private AlertsService alertsService;
    private final Clock clock;

    @GetMapping(value = LOGIN_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView loginInit(
            @RequestParam(name = "login_challenge")
            @Pattern(regexp = "^[a-f0-9]{32}$", message = "Incorrect login_challenge format") String loginChallenge,
            HttpServletRequest request,
            HttpServletResponse response) {

        RequestUtil.setFlowTraceId(loginChallenge);
        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(loginChallenge);
        request.setAttribute(LOGIN_REQUEST_INFO, loginRequestInfo);
        // At first AUTHENTICATION_REQUEST_TYPE stays null until additional logic below has decided which path to take.

        // Set locale as early as possible, so it could be used by error messages as much as possible.
        LocaleUtil.setLocaleIfUnset(request, response, loginRequestInfo);

        validateLoginRequestInfo(loginRequestInfo);

        String govssoAuthHandoverToken = loginRequestInfo.getAuthHandoverToken();
        if (govssoAuthHandoverToken != null && !ssoConfigurationProperties.isAuthHandoverEnabled()) {
            throw new SsoException(USER_INPUT, "Authentication using an auth handover token is not enabled");
        }

        if (StringUtils.isEmpty(loginRequestInfo.getSubject())) {
            if (govssoAuthHandoverToken != null) {
                request.setAttribute(AUTHENTICATION_REQUEST_TYPE, AUTH_HANDOVER);
                SignedJWT authHandoverToken = parseAuthHandoverToken(govssoAuthHandoverToken);
                UserAttributes userAttributes = parseUserAttributes(authHandoverToken);
                if (AuthHandoverTokenUtil.clientAcceptsAuthHandover(loginRequestInfo.getClient(), userAttributes,
                        ssoConfigurationProperties.getSessionMaxDuration(), clock)) {
                    return authenticateWithHandoverToken(loginRequestInfo, request, authHandoverToken, userAttributes);
                }
            }
            request.setAttribute(AUTHENTICATION_REQUEST_TYPE, START_SESSION);
            return authenticateWithTara(loginRequestInfo, response);
        } else {
            request.setAttribute(AUTHENTICATION_REQUEST_TYPE, CONTINUE_SESSION);
            if (loginRequestInfo.getClient().isSecuredApp()) {
                return reauthenticate(loginRequestInfo, request, response);
            }
            List<Consent> consents = hydraService.getValidConsentsAtRequestTime(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId(), loginRequestInfo.getRequestedAt());
            UserAttributes userAttributes = hydraService.getUserAttributesFromConsentContext(consents);
            if (userAttributes == null) {
                return reauthenticate(loginRequestInfo, request, response);
            }
            if (SecureAppUtil.isSecuredAppSession(consents)) {
                // Sessions of type `SECURED_APP_SESSION` cannot be continued, so let's remove the session cookie and
                // redirect the user back to the initial authentication endpoint. This will effectively restart the
                // authentication process and since the session cookie will be missing, a new session will be created.
                CookieUtil.deleteHydraSessionCookie(request, response);
                return new ModelAndView("redirect:" + loginRequestInfo.getRequestUrl());
            }
            if (govssoAuthHandoverToken != null) {
                SignedJWT authHandoverToken = parseAuthHandoverToken(govssoAuthHandoverToken);
                authHandoverTokenVerifier.verify(authHandoverToken);
                return reauthenticate(loginRequestInfo, request, response);
            }
            if (SecureAppUtil.isSecuredAppWebSession(consents)
                    && !AuthHandoverTokenUtil.clientAcceptsAuthHandover(loginRequestInfo.getClient(), userAttributes,
                    ssoConfigurationProperties.getSessionMaxDuration(), clock)) {
                return reauthenticate(loginRequestInfo, request, response);
            }
            if (!isSessionAcrHigherOrEqualToLoginRequestAcr(loginRequestInfo, userAttributes)) {
                return openAcrView(loginRequestInfo);
            }
            if (shouldSkipContinuationView(loginRequestInfo.getClient().getMetadata(), consents)) {
                ClientRequestMetadata metadata = clientRequestMetadataFactory.fromRequest(request);
                return acceptLogin(loginRequestInfo, consents, userAttributes, metadata);
            }
            if (!CookieUtil.isValidHydraSessionCookie(request, loginRequestInfo.getSessionId())) {
                throw new SsoException(USER_INPUT, "Unable to continue session! Oidc session cookie not found.");
            }
            return openSessionContinuationView(loginRequestInfo, userAttributes);
        }
    }

    private void validateLoginRequestInfo(LoginRequestInfo loginRequestInfo) {

        if (StringUtils.isEmpty(loginRequestInfo.getSubject())) {
            if (loginRequestInfo.isSkip()) {
                throw new SsoException(TECHNICAL_GENERAL, "Subject is null, therefore login response skip value can not be true");
            }
        } else {
            if (!loginRequestInfo.isSkip()) {
                throw new SsoException(TECHNICAL_GENERAL, "Subject exists, therefore login response skip value can not be false");
            }
        }
        LoginRequestInfoUtil.validateScopes(loginRequestInfo);
        loginRequestInfo.validateAcr();
        OidcContext oidcContext = loginRequestInfo.getOidcContext();
        Prompt prompt = loginRequestInfo.getAndValidatePrompt();
        if (oidcContext != null && oidcContext.getIdTokenHintClaims() != null) {
            throw new SsoException(USER_INPUT, "id_token_hint_claims must be null");
        }
        if (prompt != Prompt.CONSENT) {
            throw new SsoException(USER_INPUT, "Request URL must contain prompt=consent");
        }
        validateRequestedAccessTokenAudience(loginRequestInfo);
    }

    private void validateRequestedAccessTokenAudience(LoginRequestInfo loginRequestInfo) {
        String[] requestedAudience = loginRequestInfo.getRequestedAccessTokenAudience();
        if (requestedAudience != null
                && Arrays.asList(requestedAudience).contains(ssoConfigurationProperties.getBaseUrl().toString())) {
            throw new SsoException(USER_INPUT, "Requested access token audience must not contain the configured base URL");
        }
    }

    private SignedJWT parseAuthHandoverToken(String govssoAuthHandoverToken) {
        try {
            return SignedJWT.parse(govssoAuthHandoverToken);
        } catch (ParseException ex) {
            throw new SsoException(USER_INPUT, "Unable to parse govsso_auth_handover_token", ex);
        }
    }

    private UserAttributes parseUserAttributes(SignedJWT authHandoverToken) {
        try {
            return userAttributesFactory.fromAuthHandoverToken(authHandoverToken.getJWTClaimsSet());
        } catch (ParseException ex) {
            throw new SsoException(USER_INPUT, "Unable to parse user attributes from auth handover token", ex);
        }
    }

    private ModelAndView authenticateWithHandoverToken(LoginRequestInfo loginRequestInfo, HttpServletRequest request,
                                                       SignedJWT authHandoverToken, UserAttributes userAttributes) {
        authHandoverTokenVerifier.verify(authHandoverToken);
        if (loginRequestInfo.getClient().getMetadata().getClientType() != ClientType.DEFAULT) {
            throw new SsoException(USER_INPUT, "Only %s client type is allowed to use an auth handover token".formatted(ClientType.DEFAULT));
        }
        ClientRequestMetadata metadata = clientRequestMetadataFactory.fromRequest(request);
        return acceptAuthHandoverLogin(loginRequestInfo, authHandoverToken, userAttributes, metadata);
    }

    private ModelAndView authenticateWithTara(LoginRequestInfo loginRequestInfo, HttpServletResponse response) {
        LevelOfAssurance requestAcr = loginRequestInfo.getAcr();
        LevelOfAssurance requiredAcr = requestAcr != null ? requestAcr : LevelOfAssurance.DEFAULT;
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest(requiredAcr, loginRequestInfo.getChallenge());

        SsoCookie ssoCookie = SsoCookie.builder()
                .loginChallenge(loginRequestInfo.getChallenge())
                .taraAuthenticationRequestState(authenticationRequest.getState().getValue())
                .taraAuthenticationRequestNonce(authenticationRequest.getNonce().getValue())
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, ssoCookieSigner.getSignedCookieValue(ssoCookie));
        return new ModelAndView("redirect:" + authenticationRequest.toURI().toString());
    }

    private ModelAndView openSessionContinuationView(LoginRequestInfo loginRequestInfo, UserAttributes userAttributes) {
        ModelAndView model = new ModelAndView("authView");
        String[] requestedScopes = loginRequestInfo.getRequestedScope();
        String clientName = LocaleUtil.getTranslatedClientName(loginRequestInfo.getClient());

        model.addObject("givenName", userAttributes.givenName());
        model.addObject("familyName", userAttributes.familyName());
        if (userAttributes.birthdate() != null)
            model.addObject("dateOfBirth", LocalDate.parse(userAttributes.birthdate()));
        if (List.of(requestedScopes).contains(SCOPE_PHONE))
            model.addObject("phoneNumber", userAttributes.phoneNumber());
        model.addObject("subject", loginRequestInfo.getSubject());
        model.addObject("clientNameEscaped", HtmlUtils.htmlEscape(clientName, StandardCharsets.UTF_8.name()));
        model.addObject("loginChallenge", loginRequestInfo.getChallenge());
        model.addObject("logo", loginRequestInfo.getClient().getMetadata().getOidcClient().getLogo());
        if (alertsService != null) {
            model.addObject("alerts", alertsService.getStaticAndActiveAlerts());
            model.addObject("hasStaticAlert", alertsService.hasStaticAlert());
        }
        model.addObject("activeSessionCount", hydraService.getUserSessionCount(loginRequestInfo.getSubject()));
        ModelUtil.addSelfServiceUrlToModel(model, ssoConfigurationProperties.getSelfServiceUrl());
        return model;
    }

    private ModelAndView acceptLogin(LoginRequestInfo loginRequestInfo, List<Consent> consents,
                                     UserAttributes userAttributes, ClientRequestMetadata metadata) {
        LoginAcceptResponse response = hydraService.acceptContinuedSessionLogin(consents, loginRequestInfo, metadata);
        statisticsLogger.logAccept(CONTINUE_SESSION, userAttributes, loginRequestInfo);
        return new ModelAndView("redirect:" + response.getRedirectTo());
    }

    private ModelAndView acceptAuthHandoverLogin(LoginRequestInfo loginRequestInfo, JWT authHandoverToken,
                                                 UserAttributes userAttributes, ClientRequestMetadata metadata) {
        LoginAcceptResponse response = hydraService.acceptSecuredAppWebSessionLogin(authHandoverToken, loginRequestInfo, metadata);
        statisticsLogger.logAccept(AUTH_HANDOVER, userAttributes, loginRequestInfo);
        return new ModelAndView("redirect:" + response.getRedirectTo());
    }

    private ModelAndView openAcrView(LoginRequestInfo loginRequestInfo) {
        ModelAndView model = new ModelAndView("acrView");
        String clientName = LocaleUtil.getTranslatedClientName(loginRequestInfo.getClient());
        model.addObject("clientNameEscaped", HtmlUtils.htmlEscape(clientName, StandardCharsets.UTF_8.name()));
        model.addObject("loginChallenge", loginRequestInfo.getChallenge());
        model.addObject("logo", loginRequestInfo.getClient().getMetadata().getOidcClient().getLogo());
        if (alertsService != null) {
            model.addObject("alerts", alertsService.getStaticAndActiveAlerts());
            model.addObject("hasStaticAlert", alertsService.hasStaticAlert());
        }
        model.addObject("activeSessionCount", hydraService.getUserSessionCount(loginRequestInfo.getSubject()));
        ModelUtil.addSelfServiceUrlToModel(model, ssoConfigurationProperties.getSelfServiceUrl());
        return model;
    }

    private boolean shouldSkipContinuationView(Metadata metadata, List<Consent> consents) {
        if (!metadata.isDisplayUserConsent()) {
            return true;
        } else if (metadata.getSkipUserConsentClientIds() == null) {
            return false;
        } else {
            return sessionHasSkipUserConsentClientIds(consents, metadata.getSkipUserConsentClientIds());
        }
    }

    private boolean sessionHasSkipUserConsentClientIds(List<Consent> consents, List<String> skipUserConsentClientIds) {
        return consents.stream()
                .map(consent -> consent.getConsentRequest().getClient().getClientId())
                .anyMatch(skipUserConsentClientIds::contains);
    }

    private ModelAndView reauthenticate(LoginRequestInfo loginRequestInfo, HttpServletRequest
            request, HttpServletResponse response) {
        hydraService.deleteConsentBySubjectSession(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
        hydraService.deleteLoginSessionAndRelatedLoginRequests(loginRequestInfo.getSessionId());
        CookieUtil.deleteHydraSessionCookie(request, response);

        statisticsLogger.logReject(loginRequestInfo, CONTINUE_SESSION);
        return new ModelAndView("redirect:" + loginRequestInfo.getRequestUrl());
    }

    private boolean isSessionAcrHigherOrEqualToLoginRequestAcr(LoginRequestInfo loginRequestInfo,
                                                               UserAttributes userAttributes) {
        LevelOfAssurance requestAcr = loginRequestInfo.getAcr();
        LevelOfAssurance requiredAcr = requestAcr != null ? requestAcr : LevelOfAssurance.DEFAULT;
        LevelOfAssurance sessionAcr = LevelOfAssurance.findByAcrName(userAttributes.acr());
        return sessionAcr.getAcrLevel() >= requiredAcr.getAcrLevel();
    }
}
