package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.ErrorHandler;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.StatisticsLogger;
import ee.ria.govsso.session.service.hydra.AccessTokenStrategy;
import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.Consent;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookRequest;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookResponse;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookResponse.IdToken.IdTokenBuilder;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookResponse.RefreshTokenHookResponseBuilder;
import ee.ria.govsso.session.service.hydra.Representee;
import ee.ria.govsso.session.service.hydra.RepresenteeRequestStatus;
import ee.ria.govsso.session.service.paasuke.MandateTriplet;
import ee.ria.govsso.session.service.paasuke.PaasukeService;
import ee.ria.govsso.session.service.paasuke.Person;
import ee.ria.govsso.session.token.AccessTokenClaims;
import ee.ria.govsso.session.token.AccessTokenClaimsFactory;
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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static ee.ria.govsso.session.logging.StatisticsLogger.AUTHENTICATION_REQUEST_TYPE;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.UPDATE_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.CONSENT_REQUEST_INFO;
import static net.logstash.logback.marker.Markers.append;


@Slf4j
@RestController
@RequiredArgsConstructor
public class RefreshTokenHookController {
    public static final String TOKEN_REFRESH_REQUEST_MAPPING = "/admin/token-refresh";
    private final HydraService hydraService;
    private final AccessTokenClaimsFactory accessTokenClaimsFactory;
    private final PaasukeService paasukeService;
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

        validateRequestedScopes(hookRequest);

        List<Consent> consents = hydraService.getValidConsents(hookRequest.getSubject(), sessionId);
        JWT taraIdToken = hydraService.getTaraIdTokenFromConsentContext(consents);
        ConsentRequestInfo consentRequestInfo = getConsentRequestByClientId(consents, hookRequest.getClientId());

        if (taraIdToken == null || consentRequestInfo == null) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Consent has expired");
        }

        request.setAttribute(CONSENT_REQUEST_INFO, consentRequestInfo);

        JWTClaimsSet taraIdTokenClaims = taraIdToken.getJWTClaimsSet();
        IdTokenBuilder idTokenBuilder = RefreshTokenHookResponse.IdToken.builder()
                .sid(sessionId);
        RefreshTokenHookResponseBuilder responseBuilder = RefreshTokenHookResponse.builder()
                .refreshRememberFor(true)
                .rememberFor(ssoConfigurationProperties.getSessionMaxUpdateIntervalInSeconds())
                .refreshConsentRememberFor(true)
                .consentRememberFor(ssoConfigurationProperties.getSessionMaxUpdateIntervalInSeconds());
        Map<String, Object> profileAttributes = taraIdTokenClaims.getJSONObjectClaim("profile_attributes");
        idTokenBuilder
                .givenName(profileAttributes.get("given_name").toString())
                .familyName(profileAttributes.get("family_name").toString())
                .birthdate(profileAttributes.get("date_of_birth").toString());
        if (hookRequest.getGrantedScopes().contains("phone") && taraIdTokenClaims.getClaims().get("phone_number") != null) {
            idTokenBuilder
                    .phoneNumber(taraIdTokenClaims.getClaims().get("phone_number").toString())
                    .phoneNumberVerified((Boolean) taraIdTokenClaims.getClaims().get("phone_number_verified"));
        }
        RefreshTokenHookResponse.IdToken idToken = idTokenBuilder.build();

        String subject = taraIdTokenClaims.getSubject();
        String representeeSubject = getRepresenteeSubject(hookRequest);
        idToken.setRepresentee_list(getRepresentees(consentRequestInfo, subject, hookRequest));
        if (representeeSubject != null && !subject.equals(representeeSubject)) {
            Representee representee = getRepresentee(consentRequestInfo, subject, representeeSubject);
            idToken.setRepresentee(representee);
        }

        if (StringUtils.equals(AccessTokenStrategy.JWT, consentRequestInfo.getClient().getAccessTokenStrategy())) {
            AccessTokenClaims accessTokenClaims = accessTokenClaimsFactory.from(taraIdTokenClaims, hookRequest.getGrantedScopes());
            if (idToken.getRepresentee() != null) {
                accessTokenClaims.setRepresentee(idToken.getRepresentee());
            }
            responseBuilder.accessToken(accessTokenClaims);
        }

        statisticsLogger.logAccept(UPDATE_SESSION, taraIdToken, consentRequestInfo, sessionId);

        RefreshTokenHookResponse response = responseBuilder
                .idToken(idToken)
                .build();
        log.debug("Token refresh response: {}", response);
        return ResponseEntity.ok(response);
    }

    private static void validateRequestedScopes(RefreshTokenHookRequest hookRequest) {
        if (hookRequest.getRequestedScopes() != null) {
            boolean containsRepresenteeWithSubject = false;
            for (String requestedScope: hookRequest.getRequestedScopes()) {
                if (StringUtils.isEmpty(requestedScope)) {
                    continue;
                }
                if (requestedScope.startsWith("representee.") && !requestedScope.equals("representee.*")) {
                    if (!hookRequest.getGrantedScopes().contains("representee.*")) {
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
    }

    private Representee getRepresentee(
            ConsentRequestInfo consentRequestInfo, String subject, String representeeSubject) {
        Client client = consentRequestInfo.getClient();
        RepresenteeRequestStatus status = RepresenteeRequestStatus.SERVICE_NOT_AVAILABLE;
        try {
            MandateTriplet mandateTriplet =
                    paasukeService.fetchMandates(representeeSubject, subject, client.getMetadata().getPaasukeParameters());
            if (mandateTriplet.mandates().isEmpty()) {
                status = RepresenteeRequestStatus.REQUESTED_REPRESENTEE_NOT_ALLOWED;
                throw new SsoException(ErrorCode.USER_INPUT, "User is not allowed to represent provided representee");
            }
            return toHydraRepresentation(mandateTriplet);
        } catch (SsoException e) {
            log.error(append(ErrorHandler.ERROR_CODE_MARKER, e.getErrorCode().name()), e.getMessage(), e);
        }
        return Representee.builder().status(status).build();
    }

    private static Representee toHydraRepresentation(MandateTriplet mandateTriplet) {
        Person representee = mandateTriplet.representee();
        return Representee.builder()
                .status(RepresenteeRequestStatus.REQUESTED_REPRESENTEE_CURRENT)
                .type(representee.type())
                .givenName(representee.firstName())
                .familyName(representee.surname())
                .name(representee.legalName())
                .sub(representee.identifier())
                .mandates(mandateTriplet.mandates()
                        .stream()
                        .map(mandate -> Representee.Mandate.builder()
                                .role(mandate.role())
                                .build())
                        .collect(Collectors.toList())
                )
                .build();
    }

    //TODO ConsentInitController has the exact same method, refactor so it can be reused in both places.
    private Representee toHydraRepresentation(Person representee) {
        return Representee.builder()
                .type(representee.type())
                .givenName(representee.firstName())
                .familyName(representee.surname())
                .name(representee.legalName())
                .sub(representee.identifier())
                .build();
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
            if (id.isEmpty()) {
                throw new SsoException(ErrorCode.USER_INPUT, "The subject length in the representee scope must be at least 1 character or longer");
            }
            if (id.equals("*")) {
                continue;
            }
            return id;
        }
        return null;
    }

    private List<Representee> getRepresentees(
            ConsentRequestInfo consentRequestInfo, String subject, RefreshTokenHookRequest hookRequest) {
        if (hookRequest.getRequestedScopes() == null || !hookRequest.getRequestedScopes().contains("representee_list")) {
            return null;
        }
        try {
            Person[] persons = paasukeService.fetchRepresentees(subject, consentRequestInfo.getClient().getMetadata().getPaasukeParameters());
            return Arrays.stream(persons).map(this::toHydraRepresentation).toList();
        } catch (SsoException e) {
            log.error(append(ErrorHandler.ERROR_CODE_MARKER, e.getErrorCode().name()), e.getMessage(), e);
        }
        return null;
    }

    public static ConsentRequestInfo getConsentRequestByClientId(List<Consent> consents, String clientId) {
        return consents.stream()
                .map(Consent::getConsentRequest)
                .filter(consentRequestInfo -> consentRequestInfo.getClient().getClientId().equals(clientId))
                .findFirst().orElse(null);
    }
}
