package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.hydra.OidcContext;
import ee.ria.govsso.session.service.tara.TaraService;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieSigner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.thymeleaf.util.ArrayUtils;

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
            HttpServletResponse response) {

        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(loginChallenge);
        validateLoginRequestInfo(loginRequestInfo);

        OidcContext oidcContext = loginRequestInfo.getOidcContext();
        if (oidcContext != null && ArrayUtils.isEmpty(oidcContext.getAcrValues())) {
            oidcContext.setAcrValues(new String[]{"high"});
        }

        if (loginRequestInfo.getRequestUrl().contains("prompt=none")) {
            return updateSession(loginRequestInfo);
        }

        validateLoginRequestInfoForAuthenticationAndContinuation(loginRequestInfo);
        if (StringUtils.isEmpty(loginRequestInfo.getSubject())) {
            return authenticateWithTara(loginRequestInfo, response);
        } else {
            return renderSessionContinuationForm(loginRequestInfo, response);
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
            throw new SsoException(ErrorCode.USER_INPUT, "Requested scope most contain openid and nothing else");
        }

        if (oidcContext != null && !ArrayUtils.isEmpty(oidcContext.getAcrValues())) {
            if (oidcContext.getAcrValues().length > 1) {
                throw new SsoException(ErrorCode.USER_INPUT, "acrValues must contain only 1 value");

            } else if (!oidcContext.getAcrValues()[0].matches("low|substantial|high")) {
                throw new SsoException(ErrorCode.USER_INPUT, "acrValues must be one of low/substantial/high");
            }
        }
    }

    private ModelAndView updateSession(LoginRequestInfo loginRequestInfo) {
        validateLoginRequestInfoAgainstToken(loginRequestInfo);
        JWT idToken = getAndValidateIdToken(loginRequestInfo);
        String redirectUrl = hydraService.acceptLogin(loginRequestInfo.getChallenge(), idToken);
        return new ModelAndView("redirect:" + redirectUrl);
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
            throw new SsoException(ErrorCode.USER_INPUT, "Id token session id must equal request session id");
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

    private ModelAndView renderSessionContinuationForm(LoginRequestInfo loginRequestInfo, HttpServletResponse response) {
        JWT idToken = getAndValidateIdToken(loginRequestInfo);
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
            model.addObject("subject", hideCharactersExceptFirstFive(loginRequestInfo.getSubject()));
            model.addObject("clientName", loginRequestInfo.getClient().getClientName());
            model.addObject("loginChallenge", loginRequestInfo.getChallenge());
        }

        SsoCookie ssoCookie = SsoCookie.builder()
                .loginChallenge(loginRequestInfo.getChallenge())
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, ssoCookieSigner.getSignedCookieValue(ssoCookie));
        return model;
    }

    private String hideCharactersExceptFirstFive(String subject) {
        if (subject.length() > 5) {
            String visibleCharacters = subject.substring(0, 5);
            return visibleCharacters + "*".repeat(subject.length() - 5);
        }
        return subject;
    }

    private JWT getAndValidateIdToken(LoginRequestInfo loginRequestInfo) {
        JWT idToken = hydraService.getTaraIdTokenFromConsentContext(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
        try {
            JWTClaimsSet claimsSet = idToken.getJWTClaimsSet();
            String acrValue = loginRequestInfo.getOidcContext().getAcrValues()[0];
            if (!isIdTokenAcrHigherOrEqualToLoginRequestAcr(claimsSet.getStringClaim("acr"), acrValue)) {
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "ID Token acr value must be equal to or higher than hydra login request acr");
            }
        } catch (ParseException ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to parse claim set from Id token");
        }
        return idToken;
    }

    private boolean isIdTokenAcrHigherOrEqualToLoginRequestAcr(String idTokenAcr, String loginRequestInfoAcr) {
        Map<String, Integer> acrMap = Map.of("low", 1, "substantial", 2, "high", 3);
        return acrMap.get(idTokenAcr) >= acrMap.get(loginRequestInfoAcr);
    }
}
