package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.StatisticsLogger;
import ee.ria.govsso.session.service.hydra.Consent;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookRequest;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookResponse;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookResponse.RefreshTokenHookResponseBuilder;
import ee.ria.govsso.session.util.RequestUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static ee.ria.govsso.session.logging.StatisticsLogger.AUTHENTICATION_REQUEST_TYPE;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.UPDATE_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.CONSENT_REQUEST_INFO;


@Slf4j
@RestController
@RequiredArgsConstructor
public class RefreshTokenHookController {
    public static final String TOKEN_REFRESH_REQUEST_MAPPING = "/admin/token-refresh";
    private final HydraService hydraService;
    private final SsoConfigurationProperties ssoConfigurationProperties;
    private final StatisticsLogger statisticsLogger;

    @PostMapping(TOKEN_REFRESH_REQUEST_MAPPING)
    public ResponseEntity<RefreshTokenHookResponse> tokenRefresh(@RequestBody RefreshTokenHookRequest hookRequest, HttpServletRequest request) throws ParseException {
        log.debug("Token refresh request received: {}", request);

        String generatedTraceId = RandomStringUtils.random(32, "0123456789abcdef");
        RequestUtil.setFlowTraceId(generatedTraceId);
        request.setAttribute(AUTHENTICATION_REQUEST_TYPE, UPDATE_SESSION);

        String sessionId = hookRequest.getSessionId();
        if (StringUtils.isEmpty(sessionId)) {
            //TODO if no consents are found then CONSENT_REQUEST_INFO will remain empty, to fill client information in statistics logger then we can also request it from hydra by using clientId
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Hydra session was not found");
        }

        List<Consent> consents = hydraService.getValidConsents(hookRequest.getSubject(), sessionId);
        JWT idToken = hydraService.getTaraIdTokenFromConsentContext(consents);
        ConsentRequestInfo consentRequestInfo = getConsentRequestByClientId(consents, hookRequest.getClientId());

        if (idToken == null || consentRequestInfo == null) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Consent has expired");
        }

        request.setAttribute(CONSENT_REQUEST_INFO, consentRequestInfo);

        JWTClaimsSet idTokenClaims = idToken.getJWTClaimsSet();
        RefreshTokenHookResponseBuilder responseBuilder = RefreshTokenHookResponse.builder()
                .sessionId(sessionId)
                .refreshRememberFor(true)
                .rememberFor(ssoConfigurationProperties.getSessionMaxUpdateIntervalInSeconds())
                .refreshConsentRememberFor(true)
                .consentRememberFor(ssoConfigurationProperties.getSessionMaxUpdateIntervalInSeconds());
        if (idTokenClaims.getClaims().get("profile_attributes") instanceof Map profileAttributes) {
            responseBuilder
                    .givenName(profileAttributes.get("given_name").toString())
                    .familyName(profileAttributes.get("family_name").toString())
                    .birthDate(profileAttributes.get("date_of_birth").toString());
        }
        if (hookRequest.getGrantedScopes().contains("phone") && idTokenClaims.getClaims().get("phone_number") != null) {
            responseBuilder
                    .phoneNumber(idTokenClaims.getClaims().get("phone_number").toString())
                    .phoneNumberVerified((Boolean) idTokenClaims.getClaims().get("phone_number_verified"));
        }

        statisticsLogger.logAccept(UPDATE_SESSION, idToken, consentRequestInfo, sessionId);

        RefreshTokenHookResponse response = responseBuilder.build();
        log.debug("Token refresh response: {}", response);
        return ResponseEntity.ok(response);
    }

    public static ConsentRequestInfo getConsentRequestByClientId(List<Consent> consents, String clientId) {
        return consents.stream()
                .map(Consent::getConsentRequest)
                .filter(consentRequestInfo -> consentRequestInfo.getClient().getClientId().equals(clientId))
                .findFirst().orElse(null);
    }
}
