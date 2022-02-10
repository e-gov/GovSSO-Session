package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.tara.TaraService;
import ee.ria.govsso.session.session.SsoSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.thymeleaf.util.ArrayUtils;

import javax.servlet.http.HttpSession;
import javax.validation.constraints.Pattern;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;

import static ee.ria.govsso.session.error.ErrorCode.TECHNICAL_GENERAL;
import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class LoginInitController {

    public static final String LOGIN_INIT_REQUEST_MAPPING = "/login/init";
    private final HydraService hydraService;
    private final TaraService taraService;

    @GetMapping(value = LOGIN_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView loginInit(
            @RequestParam(name = "login_challenge")
            @Pattern(regexp = "^[a-f0-9]{32}$", message = "Incorrect login_challenge format") String loginChallenge,
            HttpSession session) throws ParseException {

        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(loginChallenge);

        SsoSession ssoSession = new SsoSession();
        ssoSession.setLoginChallenge(loginRequestInfo.getChallenge());
        String subject = loginRequestInfo.getSubject();

        // TODO: Temporary solution, full implementation by GSSO-170
        if (loginRequestInfo.getOidcContext().getIdTokenHintClaims() != null && loginRequestInfo.isSkip()) {
            JWT idToken = hydraService.getConsents(subject, loginRequestInfo.getSessionId());
            String redirectUrl = hydraService.acceptLogin(ssoSession.getLoginChallenge(), idToken);
            session.setAttribute(SSO_SESSION, ssoSession);
            return new ModelAndView("redirect:" + redirectUrl);
        }
        validateLoginRequestInfo(loginRequestInfo);

        if (loginRequestInfo.getOidcContext() != null && ArrayUtils.isEmpty(loginRequestInfo.getOidcContext().getAcrValues())) {
            loginRequestInfo.getOidcContext().setAcrValues(new String[]{"high"});
        }

        if (subject != null && !subject.isEmpty()) {
            if (!loginRequestInfo.isSkip()) {
                throw new SsoException(TECHNICAL_GENERAL, "Subject exists, therefore login response skip value can not be false");
            }

            JWT idToken = hydraService.getConsents(subject, loginRequestInfo.getSessionId());
            if (!isIdTokenAcrHigherOrEqualToLoginRequestAcr(idToken.getJWTClaimsSet().getStringClaim("acr"), loginRequestInfo.getOidcContext().getAcrValues()[0])) {
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "ID Token acr value must be equal to or higher than hydra login request acr");
            }
            JWTClaimsSet claimsSet = idToken.getJWTClaimsSet();
            Map<String, String> profileAttributes = (Map<String, String>) claimsSet.getClaims().get("profile_attributes");

            ModelAndView model = new ModelAndView("authView");
            model.addObject("givenName", profileAttributes.get("given_name"));
            model.addObject("familyName", profileAttributes.get("family_name"));
            model.addObject("subject", hideCharactersExceptFirstFive(subject));
            model.addObject("clientName", loginRequestInfo.getClient().getClientName());

            session.setAttribute(SSO_SESSION, ssoSession);

            return model;
        } else {
            if (loginRequestInfo.isSkip()) {
                throw new SsoException(TECHNICAL_GENERAL, "Subject is null, therefore login response skip value can not be true");
            }

            AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest(loginRequestInfo.getOidcContext().getAcrValues()[0]);
            ssoSession.setTaraAuthenticationRequestState(authenticationRequest.getState().getValue());
            ssoSession.setTaraAuthenticationRequestNonce(authenticationRequest.getNonce().getValue());
            session.setAttribute(SSO_SESSION, ssoSession);
            return new ModelAndView("redirect:" + authenticationRequest.toURI().toString());
        }
    }

    private void validateLoginRequestInfo(LoginRequestInfo loginRequestInfo) {

        if (loginRequestInfo.getRequestUrl().contains("prompt=none")) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Request URL contains prompt=none");
        } else if (!loginRequestInfo.getRequestUrl().contains("prompt=consent")) {
            throw new SsoException(ErrorCode.USER_INPUT, "Request URL does not contain prompt=consent");
        } else if (!Arrays.stream(loginRequestInfo.getRequestedScope()).toList().contains("openid") || loginRequestInfo.getRequestedScope().length != 1) {
            throw new SsoException(ErrorCode.USER_INPUT, "Requested scope most contain openid and nothing else");
        } else if (loginRequestInfo.getOidcContext() != null && loginRequestInfo.getOidcContext().getIdTokenHintClaims() != null) {
            throw new SsoException(ErrorCode.USER_INPUT, "id_token_hint_claims must be null");
        } else if (loginRequestInfo.getOidcContext() != null && !ArrayUtils.isEmpty(loginRequestInfo.getOidcContext().getAcrValues())) {
            if (loginRequestInfo.getOidcContext().getAcrValues().length > 1) {
                throw new SsoException(ErrorCode.USER_INPUT, "acrValues must contain only 1 value");
            } else if (!loginRequestInfo.getOidcContext().getAcrValues()[0].matches("low|substantial|high")) {
                throw new SsoException(ErrorCode.USER_INPUT, "acrValues must be one of low/substantial/high");
            }
        }
    }

    private String hideCharactersExceptFirstFive(String subject) {
        if (subject.length() > 5) {
            String visibleCharacters = subject.substring(0, 5);
            String hiddenCharacters = subject.substring(5);
            hiddenCharacters = hiddenCharacters.replaceAll(".", "*");
            subject = visibleCharacters + hiddenCharacters;
        }
        return subject;
    }

    private boolean isIdTokenAcrHigherOrEqualToLoginRequestAcr(String idTokenAcr, String loginRequestInfoAcr) {
        Map<String, Integer> acrMap = Map.of("low", 1, "substantial", 2, "high", 3);
        return acrMap.get(idTokenAcr) >= acrMap.get(loginRequestInfoAcr);
    }
}
