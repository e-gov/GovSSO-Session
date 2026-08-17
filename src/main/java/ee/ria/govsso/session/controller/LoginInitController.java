package ee.ria.govsso.session.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import ee.ria.govsso.session.common.ClientRequestMetadata;
import ee.ria.govsso.session.common.ClientRequestMetadataFactory;
import ee.ria.govsso.session.configuration.properties.SecurityConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
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
import ee.ria.govsso.session.util.CookieUtil;
import ee.ria.govsso.session.util.LocaleUtil;
import ee.ria.govsso.session.util.LoginRequestInfoUtil;
import ee.ria.govsso.session.util.ModelUtil;
import ee.ria.govsso.session.util.PromptUtil;
import ee.ria.govsso.session.util.RequestUtil;
import ee.ria.govsso.session.util.SecureAppUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.Pattern;
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
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static ee.ria.govsso.session.error.ErrorCode.TECHNICAL_GENERAL;
import static ee.ria.govsso.session.error.ErrorCode.USER_INPUT;
import static ee.ria.govsso.session.logging.StatisticsLogger.AUTHENTICATION_REQUEST_TYPE;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.AUTH_HANDOVER;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.CONTINUE_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.START_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.LOGIN_REQUEST_INFO;
import static ee.ria.govsso.session.service.helper.ClientScopes.SCOPE_PHONE;
import static ee.ria.govsso.session.service.hydra.HydraService.SESSION_EXPIRY_CLAIM;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class LoginInitController {

    public static final String LOGIN_INIT_REQUEST_MAPPING = "/login/init";
    public static final String AUTH_HANDOVER_TOKEN_PARAM = "govsso_auth_handover_token";

    private final SsoCookieSigner ssoCookieSigner;
    private final HydraService hydraService;
    private final TaraService taraService;
    private final StatisticsLogger statisticsLogger;
    private final SsoConfigurationProperties ssoConfigurationProperties;
    private final SecurityConfigurationProperties securityConfigurationProperties;
    private final ClientRequestMetadataFactory clientRequestMetadataFactory;
    @Autowired(required = false)
    private AlertsService alertsService;
    private final Clock clock;

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

        Prompt prompt = PromptUtil.getAndValidatePromptFromRequestUrl(loginRequestInfo.getRequestUrl());

        validateLoginRequestInfoForAuthenticationAndContinuation(loginRequestInfo, prompt);

        String govssoAuthHandoverToken = extractQueryParam(loginRequestInfo.getRequestUrl(), AUTH_HANDOVER_TOKEN_PARAM);
        if (govssoAuthHandoverToken != null) {
            if (!ssoConfigurationProperties.isAuthHandoverEnabled()) {
                throw new SsoException(USER_INPUT, "Authentication using an auth handover token is not enabled");
            }
            return authenticateWithHandoverToken(govssoAuthHandoverToken, loginRequestInfo, request);
        } else if (StringUtils.isEmpty(loginRequestInfo.getSubject())) {
            request.setAttribute(AUTHENTICATION_REQUEST_TYPE, START_SESSION);
            return authenticateWithTara(loginRequestInfo, response);
        } else {
            request.setAttribute(AUTHENTICATION_REQUEST_TYPE, CONTINUE_SESSION);
            if (loginRequestInfo.getClient().isSecuredApp()) {
                throw new SsoException(USER_INPUT, "SECURED_APP client type is not allowed to continue an existing session.");
            }
            List<Consent> consents = hydraService.getValidConsentsAtRequestTime(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId(), loginRequestInfo.getRequestedAt());
            JWT idToken = hydraService.getTaraIdTokenFromConsentContext(consents);
            if (idToken == null) {
                return reauthenticate(loginRequestInfo, request, response);
            } else if (SecureAppUtil.isSecuredAppSession(consents)) {
                throw new SsoException(USER_INPUT, "Secured app sessions are not allowed to be continued");
            } else if (!isIdTokenAcrHigherOrEqualToLoginRequestAcr(loginRequestInfo, idToken)) {
                return openAcrView(loginRequestInfo);
            } else if (shouldSkipContinuationView(loginRequestInfo.getClient().getMetadata(), consents)) {
                ClientRequestMetadata metadata = clientRequestMetadataFactory.fromRequest(request);
                return acceptLogin(loginRequestInfo, idToken, metadata);
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

    private ModelAndView authenticateWithHandoverToken(String govssoAuthHandoverToken, LoginRequestInfo loginRequestInfo,
                                                       HttpServletRequest request) {
        JWT authHandoverToken;
        try {
            authHandoverToken = SignedJWT.parse(govssoAuthHandoverToken);
        } catch (ParseException ex) {
            throw new SsoException(USER_INPUT, "Unable to parse govsso_auth_handover_token", ex);
        }
        validateAuthHandoverToken(authHandoverToken);
        if (loginRequestInfo.getClient().getMetadata().getClientType() != ClientType.DEFAULT) {
            throw new SsoException(USER_INPUT, "Only DEFAULT_APP client type is allowed to use an auth handover token");
        }
        request.setAttribute(AUTHENTICATION_REQUEST_TYPE, AUTH_HANDOVER);
        ClientRequestMetadata metadata = clientRequestMetadataFactory.fromRequest(request);
        return acceptAuthHandoverLogin(loginRequestInfo, authHandoverToken, metadata);
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
            if (List.of(requestedScopes).contains(SCOPE_PHONE))
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

    private ModelAndView acceptLogin(LoginRequestInfo loginRequestInfo, JWT idToken, ClientRequestMetadata metadata) {
        LoginAcceptResponse response = hydraService.acceptLogin(idToken, loginRequestInfo, metadata);
        statisticsLogger.logAccept(StatisticsLogger.AuthenticationRequestType.CONTINUE_SESSION, idToken, loginRequestInfo);
        return new ModelAndView("redirect:" + response.getRedirectTo());
    }

    private ModelAndView acceptAuthHandoverLogin(LoginRequestInfo loginRequestInfo, JWT authHandoverToken, ClientRequestMetadata metadata) {
        LoginAcceptResponse response = hydraService.acceptSecuredAppWebSessionLogin(authHandoverToken, loginRequestInfo, metadata);
        // TODO Add a logger method that accepts auth handover token.
//        statisticsLogger.logAccept(requestType, idToken, loginRequestInfo);
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
        try {
            LevelOfAssurance requestAcr = loginRequestInfo.getAcr();
            LevelOfAssurance requiredAcr = requestAcr != null ? requestAcr : LevelOfAssurance.DEFAULT;
            LevelOfAssurance tokenAcr = LevelOfAssurance.findByAcrName(idToken.getJWTClaimsSet().getStringClaim("acr"));
            return tokenAcr.getAcrLevel() >= requiredAcr.getAcrLevel();
        } catch (ParseException ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to parse claim set from Id token");
        }
    }

    private void validateAuthHandoverToken(JWT token) {
        JWTClaimsSet claims;
        try {
            claims = token.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to parse claim set from auth handover token");
        }
        if (!ssoConfigurationProperties.getBaseUrl().toString().equals(claims.getIssuer())) {
            throw new SsoException(ErrorCode.USER_INVALID_OIDC_REQUEST, "Auth handover token issuer does not match");
        }
        Instant now = clock.instant();
        Date issueTime = claims.getIssueTime();
        if (issueTime == null || issueTime.toInstant().isAfter(now)) {
            throw new SsoException(ErrorCode.USER_INVALID_OIDC_REQUEST, "Auth handover token issued-at time is in the future");
        }
        Date expirationTime = claims.getExpirationTime();
        if (expirationTime == null || expirationTime.toInstant().isBefore(now)) {
            throw new SsoException(ErrorCode.USER_INVALID_OIDC_REQUEST, "Auth handover token is expired");
        }
        Date sessionExpiry;
        try {
            sessionExpiry = claims.getDateClaim(SESSION_EXPIRY_CLAIM);
        } catch (ParseException e) {
            throw new SsoException(ErrorCode.USER_INVALID_OIDC_REQUEST,
                    "Auth handover token %s claim is not a valid date".formatted(SESSION_EXPIRY_CLAIM));
        }
        if (sessionExpiry == null) {
            throw new SsoException(ErrorCode.USER_INVALID_OIDC_REQUEST,
                    "Auth handover token does not contain %s claim".formatted(SESSION_EXPIRY_CLAIM));
        }
        if (sessionExpiry.toInstant().isBefore(now)) {
            throw new SsoException(ErrorCode.USER_INVALID_OIDC_REQUEST,
                    "Session handed over by the auth handover token has expired");
        }
    }

    private JWT createAuthHandoverIdToken(JWT authHandoverToken) {
        JWTClaimsSet handoverClaims;
        try {
            handoverClaims = authHandoverToken.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new SsoException(TECHNICAL_GENERAL, "Failed to parse claim set from auth handover token");
        }

        Map<String, Object> profileAttributes = new LinkedHashMap<>();
        profileAttributes.put("given_name", handoverClaims.getClaim("given_name"));
        profileAttributes.put("family_name", handoverClaims.getClaim("family_name"));
        profileAttributes.put("date_of_birth", handoverClaims.getClaim("birthdate"));

        JWTClaimsSet.Builder taraIdTokenClaims = new JWTClaimsSet.Builder()
                .subject(handoverClaims.getSubject())
                .issueTime(handoverClaims.getIssueTime())
                .claim("acr", handoverClaims.getClaim("acr"))
                .claim("amr", handoverClaims.getClaim("amr"))
                .claim("profile_attributes", profileAttributes);
        if (handoverClaims.getClaim("phone_number") != null) {
            taraIdTokenClaims.claim("phone_number", handoverClaims.getClaim("phone_number"));
            taraIdTokenClaims.claim("phone_number_verified", handoverClaims.getClaim("phone_number_verified"));
        }

        try {
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), taraIdTokenClaims.build());
            signedJWT.sign(new MACSigner(securityConfigurationProperties.getCookieSigningSecret()));
            return SignedJWT.parse(signedJWT.serialize());
        } catch (JOSEException | ParseException e) {
            throw new SsoException(TECHNICAL_GENERAL, "Failed to create auth handover ID token", e);
        }
    }

    private String extractQueryParam(URL url, String paramName) {
        try {
            return UriComponentsBuilder.fromUri(url.toURI())
                    .build()
                    .getQueryParams()
                    .getFirst(paramName);
        } catch (URISyntaxException e) {
            throw new SsoException(USER_INPUT, "Failed to parse auth handover token from the query parameters");
        }
    }
}
