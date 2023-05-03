package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.SignedJWT;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.StatisticsLogger;
import ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LevelOfAssurance;
import ee.ria.govsso.session.service.hydra.LoginAcceptResponse;
import ee.ria.govsso.session.service.hydra.LoginRejectResponse;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.tara.TaraService;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieValue;
import ee.ria.govsso.session.util.RequestUtil;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;
import org.thymeleaf.util.ArrayUtils;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.Pattern;

import static ee.ria.govsso.session.logging.StatisticsLogger.AUTHENTICATION_REQUEST_TYPE;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.START_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.LOGIN_REQUEST_INFO;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class AuthCallbackController {

    public static final String CALLBACK_REQUEST_MAPPING = "/login/taracallback";
    private final TaraService taraService;
    private final HydraService hydraService;
    private final StatisticsLogger statisticsLogger;

    @GetMapping(value = CALLBACK_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView loginCallback(
            @RequestParam(name = "code", required = false) @Pattern(regexp = "^[A-Za-z0-9\\-_.]{6,87}$") String code,
            @RequestParam(name = "state") @Pattern(regexp = "^[A-Za-z0-9\\-_]{43}$") String state,
            @RequestParam(name = "error", required = false) @Pattern(regexp = "user_cancel", message = "the only supported value is: 'user_cancel'") String error,
            @RequestHeader(value = HttpHeaders.USER_AGENT, required = false) String userAgent,
            @SsoCookieValue SsoCookie ssoCookie,
            HttpServletRequest request) {

        RequestUtil.setFlowTraceId(ssoCookie.getLoginChallenge());
        request.setAttribute(AUTHENTICATION_REQUEST_TYPE, START_SESSION);

        validateSsoCookie(state, ssoCookie);

        if (error != null) {
            LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(ssoCookie.getLoginChallenge());
            request.setAttribute(LOGIN_REQUEST_INFO, loginRequestInfo);

            LoginRejectResponse response = hydraService.rejectLogin(ssoCookie.getLoginChallenge());
            statisticsLogger.logReject(loginRequestInfo, START_SESSION);
            return new RedirectView(response.getRedirectTo().toString());
        }
        if (code == null) {
            throw new SsoException(ErrorCode.USER_INPUT, "code parameter must not be null");
        }

        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(ssoCookie.getLoginChallenge());
        request.setAttribute(LOGIN_REQUEST_INFO, loginRequestInfo);

        SignedJWT idToken = taraService.requestIdToken(code);
        verifyAcr(idToken, loginRequestInfo);
        taraService.verifyIdToken(ssoCookie.getTaraAuthenticationRequestNonce(), idToken, ssoCookie.getLoginChallenge());

        return acceptLogin(ssoCookie, loginRequestInfo, idToken, request.getRemoteAddr(), userAgent);
    }

    @SneakyThrows
    private void verifyAcr(SignedJWT idToken, LoginRequestInfo loginRequestInfo) {
        String idTokenAcr = idToken.getJWTClaimsSet().getStringClaim("acr");
        String loginRequestAcr = LevelOfAssurance.HIGH.getAcrName();

        if (loginRequestInfo.getOidcContext() != null
                && !ArrayUtils.isEmpty(loginRequestInfo.getOidcContext().getAcrValues())
                && !loginRequestInfo.getOidcContext().getAcrValues()[0].isEmpty()) {
            loginRequestAcr = loginRequestInfo.getOidcContext().getAcrValues()[0];
        }

        if (LevelOfAssurance.findByAcrName(idTokenAcr).getAcrLevel() < LevelOfAssurance.findByAcrName(loginRequestAcr).getAcrLevel()) {
            throw new SsoException(ErrorCode.USER_INPUT, "ID Token acr value must be equal to or higher than hydra login request acr");
        }
    }

    private void validateSsoCookie(String state, SsoCookie ssoCookie) {
        if (ssoCookie.getTaraAuthenticationRequestState() == null || ssoCookie.getTaraAuthenticationRequestState().isBlank()) {
            throw new SsoException(ErrorCode.USER_INPUT, "Session tara authentication request state must not be null");
        }
        if (!ssoCookie.getTaraAuthenticationRequestState().equals(state)) {
            throw new SsoException(ErrorCode.USER_INPUT, "Invalid TARA callback state");
        }
        if (ssoCookie.getTaraAuthenticationRequestNonce() == null || ssoCookie.getTaraAuthenticationRequestNonce().isBlank()) {
            throw new SsoException(ErrorCode.USER_INPUT, "Session tara authentication request nonce must not be null");
        }
    }

    private RedirectView acceptLogin(SsoCookie ssoCookie, LoginRequestInfo loginRequestInfo, SignedJWT idToken, String ipAddress, String userAgent) {
        LoginAcceptResponse response = hydraService.acceptLogin(ssoCookie.getLoginChallenge(), idToken, ipAddress, userAgent);
        statisticsLogger.logAccept(AuthenticationRequestType.START_SESSION, idToken, loginRequestInfo);
        return new RedirectView(response.getRedirectTo().toString());
    }
}
