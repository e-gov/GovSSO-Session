package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.StatisticsLogger;
import ee.ria.govsso.session.service.alerts.AlertsService;
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
import ee.ria.govsso.session.util.CookieUtil;
import ee.ria.govsso.session.util.LocaleUtil;
import ee.ria.govsso.session.util.ModelUtil;
import ee.ria.govsso.session.util.PromptUtil;
import ee.ria.govsso.session.util.RequestUtil;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.HtmlUtils;
import org.thymeleaf.util.ArrayUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.Pattern;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static ee.ria.govsso.session.error.ErrorCode.TECHNICAL_GENERAL;
import static ee.ria.govsso.session.error.ErrorCode.USER_INPUT;
import static ee.ria.govsso.session.logging.StatisticsLogger.AUTHENTICATION_REQUEST_TYPE;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.CONTINUE_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.START_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.LOGIN_REQUEST_INFO;

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
    @Autowired(required = false)
    private AlertsService alertsService;

    @GetMapping(value = LOGIN_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView loginInit(
            @RequestParam(name = "login_challenge")
            @Pattern(regexp = "^[a-f0-9]{32}$", message = "Incorrect login_challenge format") String loginChallenge,
            @RequestHeader(value = HttpHeaders.USER_AGENT, required = false) String userAgent,
            HttpServletRequest request,
            HttpServletResponse response) {

        RequestUtil.setFlowTraceId(loginChallenge);
        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(loginChallenge);
        request.setAttribute(LOGIN_REQUEST_INFO, loginRequestInfo);
        // At first AUTHENTICATION_REQUEST_TYPE stays null until additional logic below has decided which path to take.

        // Set locale as early as possible, so it could be used by error messages as much as possible.
        LocaleUtil.setLocaleIfUnset(request, response, loginRequestInfo);

        validateLoginRequestInfo(loginRequestInfo);

        OidcContext oidcContext = loginRequestInfo.getOidcContext();
        if (oidcContext != null && ArrayUtils.isEmpty(oidcContext.getAcrValues())) {
            oidcContext.setAcrValues(new String[]{LevelOfAssurance.HIGH.getAcrName()});
        }

        Prompt prompt = PromptUtil.getAndValidatePromptFromRequestUrl(loginRequestInfo.getRequestUrl());

        validateLoginRequestInfoForAuthenticationAndContinuation(loginRequestInfo, prompt);
        if (StringUtils.isEmpty(loginRequestInfo.getSubject())) {
            request.setAttribute(AUTHENTICATION_REQUEST_TYPE, START_SESSION);
            return authenticateWithTara(loginRequestInfo, response);
        } else {
            request.setAttribute(AUTHENTICATION_REQUEST_TYPE, CONTINUE_SESSION);
            List<Consent> consents = hydraService.getValidConsentsAtRequestTime(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId(), loginRequestInfo.getRequestedAt());
            JWT idToken = hydraService.getTaraIdTokenFromConsentContext(consents);
            if (idToken == null) {
                return reauthenticate(loginRequestInfo, request, response);
            } else if (!isIdTokenAcrHigherOrEqualToLoginRequestAcr(loginRequestInfo, idToken)) {
                return openAcrView(loginRequestInfo);
            } else if (shouldSkipContinuationView(loginRequestInfo.getClient().getMetadata(), consents)) {
                return acceptLogin(loginRequestInfo, idToken, request.getRemoteAddr(), userAgent);
            } else {
                if (CookieUtil.isValidHydraSessionCookie(request, loginRequestInfo.getSessionId())) {
                    return openSessionContinuationView(loginRequestInfo, idToken);
                } else {
                    throw new SsoException(USER_INPUT, "Unable to continue session! Oidc session cookie not found.");
                }
            }
        }
    }

    private void validateLoginRequestInfo(LoginRequestInfo loginRequestInfo) {
        OidcContext oidcContext = loginRequestInfo.getOidcContext();
        String[] requestedScopes = loginRequestInfo.getRequestedScope();

        if (StringUtils.isEmpty(loginRequestInfo.getSubject())) {
            if (loginRequestInfo.isSkip()) {
                throw new SsoException(TECHNICAL_GENERAL, "Subject is null, therefore login response skip value can not be true");
            }
        } else {
            if (!loginRequestInfo.isSkip()) {
                throw new SsoException(TECHNICAL_GENERAL, "Subject exists, therefore login response skip value can not be false");
            }
        }

        if (!Arrays.asList(requestedScopes).contains("openid") ||
                !Arrays.stream(requestedScopes).allMatch(s -> s.matches("^(openid|phone)$")) ||
                requestedScopes.length > 2) {
            throw new SsoException(USER_INPUT, "Requested scope must contain openid and may contain phone, but nothing else");
        }

        if (oidcContext != null && !ArrayUtils.isEmpty(oidcContext.getAcrValues())) {
            if (oidcContext.getAcrValues().length > 1) {
                throw new SsoException(USER_INPUT, "acrValues must contain only 1 value");

            } else if (LevelOfAssurance.findByAcrName(oidcContext.getAcrValues()[0]) == null) {
                throw new SsoException(USER_INPUT, "acrValues must be one of low/substantial/high");
            }
        }
    }

    private void validateLoginRequestInfoForAuthenticationAndContinuation(LoginRequestInfo loginRequestInfo, Prompt prompt) {
        OidcContext oidcContext = loginRequestInfo.getOidcContext();
        if (oidcContext != null && oidcContext.getIdTokenHintClaims() != null) {
            throw new SsoException(USER_INPUT, "id_token_hint_claims must be null");
        }

        if (prompt != Prompt.CONSENT) {
            throw new SsoException(USER_INPUT, "Request URL must contain prompt=consent");
        }
    }

    private ModelAndView authenticateWithTara(LoginRequestInfo loginRequestInfo, HttpServletResponse response) {
        String acrValue = loginRequestInfo.getOidcContext().getAcrValues()[0];
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest(acrValue, loginRequestInfo.getChallenge());

        SsoCookie ssoCookie = SsoCookie.builder()
                .loginChallenge(loginRequestInfo.getChallenge())
                .taraAuthenticationRequestState(authenticationRequest.getState().getValue())
                .taraAuthenticationRequestNonce(authenticationRequest.getNonce().getValue())
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, ssoCookieSigner.getSignedCookieValue(ssoCookie));
        return new ModelAndView("redirect:" + authenticationRequest.toURI().toString());
    }

    @SneakyThrows
    private ModelAndView openSessionContinuationView(LoginRequestInfo loginRequestInfo, JWT idToken) {
        ModelAndView model = new ModelAndView("authView");
        JWTClaimsSet claimsSet = idToken.getJWTClaimsSet();
        String[] requestedScopes = loginRequestInfo.getRequestedScope();

        if (claimsSet.getClaims().get("profile_attributes") instanceof Map profileAttributes) {
            String clientName = LocaleUtil.getTranslatedClientName(loginRequestInfo.getClient());

            model.addObject("givenName", profileAttributes.get("given_name"));
            model.addObject("familyName", profileAttributes.get("family_name"));
            if (profileAttributes.get("date_of_birth") != null)
                model.addObject("dateOfBirth", LocalDate.parse((String) profileAttributes.get("date_of_birth")));
            if (List.of(requestedScopes).contains("phone"))
                model.addObject("phoneNumber", claimsSet.getClaims().get("phone_number"));
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
        }
        return model;
    }

    private ModelAndView acceptLogin(LoginRequestInfo loginRequestInfo, JWT idToken, String ipAddress, String userAgent) {
        LoginAcceptResponse response = hydraService.acceptLogin(loginRequestInfo.getChallenge(), idToken, ipAddress, userAgent);
        statisticsLogger.logAccept(StatisticsLogger.AuthenticationRequestType.CONTINUE_SESSION, idToken, loginRequestInfo);
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
        for (Consent consent : consents) {
            if (skipUserConsentClientIds.contains(consent.getConsentRequest().getClient().getClientId())) {
                return true;
            }
        }
        return false;
    }

    private ModelAndView reauthenticate(LoginRequestInfo loginRequestInfo, HttpServletRequest
            request, HttpServletResponse response) {
        hydraService.deleteConsentBySubjectSession(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
        hydraService.deleteLoginSessionAndRelatedLoginRequests(loginRequestInfo.getSessionId());
        CookieUtil.deleteHydraSessionCookie(request, response);

        statisticsLogger.logReject(loginRequestInfo, CONTINUE_SESSION);
        return new ModelAndView("redirect:" + loginRequestInfo.getRequestUrl());
    }

    private boolean isIdTokenAcrHigherOrEqualToLoginRequestAcr(LoginRequestInfo loginRequestInfo, JWT idToken) {
        String loginRequestInfoAcr = loginRequestInfo.getOidcContext().getAcrValues()[0];
        String idTokenAcr;

        try {
            idTokenAcr = idToken.getJWTClaimsSet().getStringClaim("acr");
        } catch (ParseException ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to parse claim set from Id token");
        }

        return LevelOfAssurance.findByAcrName(idTokenAcr).getAcrLevel()
                >= LevelOfAssurance.findByAcrName(loginRequestInfoAcr).getAcrLevel();
    }
}
