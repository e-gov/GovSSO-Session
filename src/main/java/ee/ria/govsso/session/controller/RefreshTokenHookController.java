package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.StatisticsLogger;
import ee.ria.govsso.session.service.hydra.AccessTokenStrategy;
import ee.ria.govsso.session.service.hydra.ClientType;
import ee.ria.govsso.session.service.hydra.Consent;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookRequest;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookResponse;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookResponse.IdToken.IdTokenBuilder;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookResponse.RefreshTokenHookResponseBuilder;
import ee.ria.govsso.session.service.hydra.Representee;
import ee.ria.govsso.session.service.hydra.RepresenteeList;
import ee.ria.govsso.session.service.paasuke.RepresentationService;
import ee.ria.govsso.session.token.AccessTokenClaims;
import ee.ria.govsso.session.token.AccessTokenClaimsFactory;
import ee.ria.govsso.session.token.UserAttributes;
import ee.ria.govsso.session.util.RequestUtil;
import ee.ria.govsso.session.util.SecureAppUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

import static ee.ria.govsso.session.logging.StatisticsLogger.AUTHENTICATION_REQUEST_TYPE;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.UPDATE_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.CONSENT_REQUEST_INFO;
import static ee.ria.govsso.session.service.helper.ClientScopes.SCOPE_AUTH_HANDOVER;
import static ee.ria.govsso.session.service.helper.ClientScopes.SCOPE_PHONE;
import static ee.ria.govsso.session.service.helper.ClientScopes.SCOPE_REPRESENTEE;
import static ee.ria.govsso.session.service.helper.ClientScopes.SCOPE_REPRESENTEE_LIST;


@Slf4j
@RestController
@RequiredArgsConstructor
public class RefreshTokenHookController {
    public static final String TOKEN_REFRESH_REQUEST_MAPPING = "/admin/token-refresh";
    private final HydraService hydraService;
    private final AccessTokenClaimsFactory accessTokenClaimsFactory;
    private final RepresentationService representationService;
    private final SsoConfigurationProperties ssoConfigurationProperties;
    private final StatisticsLogger statisticsLogger;

    @PostMapping(TOKEN_REFRESH_REQUEST_MAPPING)
    public ResponseEntity<RefreshTokenHookResponse> tokenRefresh(@RequestBody RefreshTokenHookRequest hookRequest, HttpServletRequest request) {
        log.debug("Token refresh request received: {}", request);

        String generatedTraceId = RandomStringUtils.secure().next(32, "0123456789abcdef");
        RequestUtil.setFlowTraceId(generatedTraceId);
        request.setAttribute(AUTHENTICATION_REQUEST_TYPE, UPDATE_SESSION);

        String sessionId = hookRequest.getSessionId();
        if (StringUtils.isEmpty(sessionId)) {
            //TODO if no consents are found then CONSENT_REQUEST_INFO will remain empty, to fill client information in statistics logger then we can also request it from hydra by using clientId
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Hydra session was not found");
        }

        validateRequestedScopes(hookRequest);

        List<Consent> consents = hydraService.getValidConsents(hookRequest.getSubject(), sessionId);
        UserAttributes userAttributes = hydraService.getUserAttributesFromConsentContext(consents);
        ConsentRequestInfo consentRequestInfo = getConsentRequestByClientId(consents, hookRequest.getClientId());

        if (userAttributes == null || consentRequestInfo == null) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Consent has expired");
        }

        request.setAttribute(CONSENT_REQUEST_INFO, consentRequestInfo);

        RefreshTokenHookResponseBuilder responseBuilder = RefreshTokenHookResponse.builder();
        boolean isLongLivingSession = SecureAppUtil.isSecuredAppSession(consentRequestInfo);
        if (isLongLivingSession) {
            responseBuilder
                    .refreshRememberFor(false)
                    .refreshConsentRememberFor(false);
        } else {
            int rememberFor = Math.toIntExact(ssoConfigurationProperties.getSessionMaxUpdateInterval().toSeconds());
            responseBuilder
                    .refreshRememberFor(true)
                    .rememberFor(rememberFor)
                    .refreshConsentRememberFor(true)
                    .consentRememberFor(rememberFor);
        }
        IdTokenBuilder idTokenBuilder = RefreshTokenHookResponse.IdToken.builder()
                .sid(sessionId)
                .givenName(userAttributes.givenName())
                .familyName(userAttributes.familyName())
                .birthdate(userAttributes.birthdate())
                .initiator(isLongLivingSession ? ClientType.SECURED_APP : null);
        if (hookRequest.getGrantedScopes().contains(SCOPE_PHONE) && userAttributes.phoneNumber() != null) {
            idTokenBuilder
                    .phoneNumber(userAttributes.phoneNumber())
                    .phoneNumberVerified(userAttributes.phoneNumberVerified());
        }

        String subject = userAttributes.subject();
        String representeeSubject = getRepresenteeSubject(hookRequest);
        idTokenBuilder.representeeList(getRepresentees(consentRequestInfo, subject, hookRequest));
        if (representeeSubject != null && !subject.equals(representeeSubject)) {
            Representee representee = representationService.getRepresentee(consentRequestInfo, subject, representeeSubject);
            idTokenBuilder.representee(representee);
        }
        RefreshTokenHookResponse.IdToken idToken = idTokenBuilder.build();

        if (StringUtils.equals(AccessTokenStrategy.JWT, consentRequestInfo.getClient().getAccessTokenStrategy())) {
            AccessTokenClaims accessTokenClaims = accessTokenClaimsFactory.from(
                    userAttributes, hookRequest.getGrantedScopes(), isLongLivingSession, consentRequestInfo.getAuthenticatedAt().toInstant());
            if (idToken.getRepresentee() != null) {
                accessTokenClaims.setRepresentee(idToken.getRepresentee());
            }
            responseBuilder.accessToken(accessTokenClaims);
        }

        statisticsLogger.logAccept(UPDATE_SESSION, userAttributes, consentRequestInfo, sessionId);

        RefreshTokenHookResponse response = responseBuilder
                .idToken(idToken)
                .build();
        log.debug("Token refresh response: {}", response);
        return ResponseEntity.ok(response);
    }

    private void validateRequestedScopes(RefreshTokenHookRequest hookRequest) {
        List<String> requestedScopes = hookRequest.getRequestedScopes();
        if (requestedScopes == null) {
            return;
        }
        if (requestedScopes.contains(SCOPE_AUTH_HANDOVER)) {
            if (!ssoConfigurationProperties.isAuthHandoverEnabled()) {
                throw new SsoException(ErrorCode.USER_INVALID_OIDC_REQUEST, "Refresh token hook request must not contain auth handover scope because issuing auth handover tokens is disabled.");
            }
            return;
        }
        boolean containsRepresenteeWithSubject = false;
        for (String requestedScope: requestedScopes) {
            if (StringUtils.isEmpty(requestedScope)) {
                continue;
            }
            if (requestedScope.startsWith("representee.") && !requestedScope.equals(SCOPE_REPRESENTEE)) {
                if (!hookRequest.getGrantedScopes().contains(SCOPE_REPRESENTEE)) {
                    throw new SsoException(ErrorCode.USER_INVALID_OIDC_REQUEST, "Refresh token hook request must not contain a representee scope with subject when 'representee.*' is not in the list of granted scopes.");
                }
                if (containsRepresenteeWithSubject) {
                    throw new SsoException(ErrorCode.USER_INVALID_OIDC_REQUEST, "Refresh token hook request must not contain multiple representee scopes with subjects.");
                }
                containsRepresenteeWithSubject = true;
            } else if (!hookRequest.getGrantedScopes().contains(requestedScope)) {
                throw new SsoException(ErrorCode.USER_INVALID_OIDC_REQUEST, "Refresh token hook request must not contain a requested scope that is not in the list of granted scopes.");
            }
        }
    }

    private String getRepresenteeSubject(RefreshTokenHookRequest hookRequest) {
        if (hookRequest.getRequestedScopes() == null) {
            return null;
        }
        for (String requestedScope : hookRequest.getRequestedScopes()) {
            if (requestedScope == null || !requestedScope.startsWith("representee.")) {
                continue;
            }
            String id = StringUtils.substringAfter(requestedScope, ".");
            if (id.equals("*")) {
                continue;
            }
            return id;
        }
        return null;
    }

    private RepresenteeList getRepresentees(ConsentRequestInfo consentRequestInfo, String subject, RefreshTokenHookRequest hookRequest) {
        if (hookRequest.getRequestedScopes() == null || !hookRequest.getRequestedScopes().contains(SCOPE_REPRESENTEE_LIST)) {
            return null;
        }
        return representationService.getRepresentees(consentRequestInfo, subject);
    }

    public static ConsentRequestInfo getConsentRequestByClientId(List<Consent> consents, String clientId) {
        return consents.stream()
                .map(Consent::getConsentRequest)
                .filter(consentRequestInfo -> consentRequestInfo.getClient().getClientId().equals(clientId))
                .findFirst().orElse(null);
    }
}
