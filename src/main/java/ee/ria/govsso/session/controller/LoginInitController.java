package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LevelOfAssurance;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.hydra.OidcContext;
import ee.ria.govsso.session.service.tara.TaraService;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieSigner;
import ee.ria.govsso.session.util.CookieUtil;
import ee.ria.govsso.session.util.LocaleUtil;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.thymeleaf.util.ArrayUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.Pattern;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static ee.ria.govsso.session.error.ErrorCode.TECHNICAL_GENERAL;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class LoginInitController {

    public static final String LOGIN_INIT_REQUEST_MAPPING = "/login/init";

    private final SsoCookieSigner ssoCookieSigner;
    private final HydraService hydraService;
    private final TaraService taraService;

    @GetMapping(value = LOGIN_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView loginInit(
            @RequestParam(name = "login_challenge")
            @Pattern(regexp = "^[a-f0-9]{32}$", message = "Incorrect login_challenge format") String loginChallenge,
            @RequestParam(name = "lang", required = false) String language,
            @CookieValue(value = "__Host-LOCALE", required = false) String localeCookie,
            HttpServletRequest request,
            HttpServletResponse response) {

        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(loginChallenge);

        if (language == null && localeCookie == null) {
            //Set locale as early as possible so it could be used by error messages as much as possible.
            LocaleUtil.setLocale(loginRequestInfo);
        }
        validateLoginRequestInfo(loginRequestInfo);

        OidcContext oidcContext = loginRequestInfo.getOidcContext();
        if (oidcContext != null && ArrayUtils.isEmpty(oidcContext.getAcrValues())) {
            oidcContext.setAcrValues(new String[]{LevelOfAssurance.HIGH.getAcrName()});
        }

        if (loginRequestInfo.getRequestUrl().contains("prompt=none")) {
            return updateSession(loginRequestInfo, request, response);
        }

        validateLoginRequestInfoForAuthenticationAndContinuation(loginRequestInfo);
        if (StringUtils.isEmpty(loginRequestInfo.getSubject())) {
            return authenticateWithTara(loginRequestInfo, response);
        } else {
            JWT idToken = hydraService.getTaraIdTokenFromConsentContext(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
            if (idToken == null) {
                return reauthenticate(loginRequestInfo, request, response);
            } else {
                return sessionContinuationView(loginRequestInfo, idToken);
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

        if (!Arrays.asList(requestedScopes).contains("openid") || requestedScopes.length != 1) {
            throw new SsoException(ErrorCode.USER_INPUT, "Requested scope must contain openid and nothing else");
        }

        if (oidcContext != null && !ArrayUtils.isEmpty(oidcContext.getAcrValues())) {
            if (oidcContext.getAcrValues().length > 1) {
                throw new SsoException(ErrorCode.USER_INPUT, "acrValues must contain only 1 value");

            } else if (LevelOfAssurance.findByAcrName(oidcContext.getAcrValues()[0]) == null) {
                throw new SsoException(ErrorCode.USER_INPUT, "acrValues must be one of low/substantial/high");
            }
        }
    }

    private ModelAndView updateSession(LoginRequestInfo loginRequestInfo, HttpServletRequest request, HttpServletResponse response) {
        validateLoginRequestInfoAgainstToken(loginRequestInfo);
        JWT idToken = hydraService.getTaraIdTokenFromConsentContext(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
        if (idToken == null) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "No valid consent requests found");
        } else {
            validateIdToken(loginRequestInfo, idToken);
            String redirectUrl = hydraService.acceptLogin(loginRequestInfo.getChallenge(), idToken);
            return new ModelAndView("redirect:" + redirectUrl);
        }
    }

    private void validateLoginRequestInfoAgainstToken(LoginRequestInfo loginRequestInfo) {
        if (StringUtils.isEmpty(loginRequestInfo.getSubject())) {
            throw new SsoException(ErrorCode.USER_INPUT, "Subject cannot be empty for session update");
        }
        if (loginRequestInfo.getOidcContext() == null) {
            throw new SsoException(ErrorCode.USER_INPUT, "Oidc context cannot be empty for session update");
        }

        Map<String, Object> idTokenHintClaims = loginRequestInfo.getOidcContext().getIdTokenHintClaims();
        if (idTokenHintClaims == null || idTokenHintClaims.isEmpty()) {
            throw new SsoException(ErrorCode.USER_INPUT, "Id token cannot be empty for session update");
        }

        @SuppressWarnings("unchecked")
        List<String> audiences = (List<String>) idTokenHintClaims.get("aud");
        if (!audiences.contains(loginRequestInfo.getClient().getClientId())) {
            throw new SsoException(ErrorCode.USER_INPUT, "Id token audiences must contain request client id");
        }
        if (!idTokenHintClaims.get("sid").equals(loginRequestInfo.getSessionId())) {
            throw new SsoException(ErrorCode.USER_INPUT, "Id token session id must equal request session id"); // TODO: Re-Authenticate?
        }

        Integer tokenExpirationDateInSeconds = (Integer) idTokenHintClaims.get("exp");
        Instant tokenExpirationTime = Instant.ofEpochSecond(tokenExpirationDateInSeconds);
        if (Instant.now().isAfter(tokenExpirationTime)) {
            throw new SsoException(ErrorCode.USER_INPUT, "Id token must not be expired");
        }
    }

    private void validateLoginRequestInfoForAuthenticationAndContinuation(LoginRequestInfo loginRequestInfo) {
        if (!loginRequestInfo.getRequestUrl().contains("prompt=consent")) {
            throw new SsoException(ErrorCode.USER_INPUT, "Request URL must contain prompt=consent");
        }
        OidcContext oidcContext = loginRequestInfo.getOidcContext();
        if (oidcContext != null && oidcContext.getIdTokenHintClaims() != null) {
            throw new SsoException(ErrorCode.USER_INPUT, "id_token_hint_claims must be null");
        }
    }

    private ModelAndView authenticateWithTara(LoginRequestInfo loginRequestInfo, HttpServletResponse response) {
        String acrValue = loginRequestInfo.getOidcContext().getAcrValues()[0];
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest(acrValue);

        SsoCookie ssoCookie = SsoCookie.builder()
                .loginChallenge(loginRequestInfo.getChallenge())
                .taraAuthenticationRequestState(authenticationRequest.getState().getValue())
                .taraAuthenticationRequestNonce(authenticationRequest.getNonce().getValue())
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, ssoCookieSigner.getSignedCookieValue(ssoCookie));
        return new ModelAndView("redirect:" + authenticationRequest.toURI().toString());
    }

    @SneakyThrows
    private ModelAndView sessionContinuationView(LoginRequestInfo loginRequestInfo, JWT idToken) {
        validateIdToken(loginRequestInfo, idToken);
        ModelAndView model = new ModelAndView("authView");
        JWTClaimsSet claimsSet;
        try {
            claimsSet = idToken.getJWTClaimsSet();
        } catch (ParseException ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to parse claim set from Id token");
        }
        if (claimsSet.getClaims().get("profile_attributes") instanceof Map profileAttributes) {
            model.addObject("givenName", profileAttributes.get("given_name"));
            model.addObject("familyName", profileAttributes.get("family_name"));
            model.addObject("dateOfBirth", profileAttributes.get("date_of_birth"));
            if (profileAttributes.get("date_of_birth") != null)
                model.addObject("dateOfBirth", LocaleUtil.formatDateWithLocale((String) profileAttributes.get("date_of_birth")));
            model.addObject("subject", loginRequestInfo.getSubject());
            model.addObject("clientName", LocaleUtil.getTranslatedClientName(loginRequestInfo.getClient()));
            model.addObject("loginChallenge", loginRequestInfo.getChallenge());
        }
        return model;
    }

    private ModelAndView reauthenticate(LoginRequestInfo loginRequestInfo, HttpServletRequest request, HttpServletResponse response) {
        hydraService.deleteConsentBySubjectSession(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
        hydraService.deleteLoginSessionAndRelatedLoginRequests(loginRequestInfo.getSessionId());
        CookieUtil.deleteHydraSessionCookie(request, response);
        return new ModelAndView("redirect:" + loginRequestInfo.getRequestUrl());
    }

    private void validateIdToken(LoginRequestInfo loginRequestInfo, JWT idToken) {
        try {
            JWTClaimsSet claimsSet = idToken.getJWTClaimsSet();
            String acrValue = loginRequestInfo.getOidcContext().getAcrValues()[0];
            if (!isIdTokenAcrHigherOrEqualToLoginRequestAcr(claimsSet.getStringClaim("acr"), acrValue)) {
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "ID Token acr value must be equal to or higher than hydra login request acr");
            }
        } catch (ParseException ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to parse claim set from Id token");
        }
    }

    private boolean isIdTokenAcrHigherOrEqualToLoginRequestAcr(String idTokenAcr, String loginRequestInfoAcr) {
        return LevelOfAssurance.findByAcrName(idTokenAcr).getAcrLevel() >= LevelOfAssurance.findByAcrName(loginRequestInfoAcr).getAcrLevel();
    }
}
