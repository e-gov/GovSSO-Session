package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.service.hydra.Consent;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LevelOfAssurance;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookRequest;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookRequest.IdToken;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookResponse;
import ee.ria.govsso.session.service.hydra.RefreshTokenHookResponse.RefreshTokenHookResponseBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpStatus.FORBIDDEN;


@Slf4j
@RestController
@RequiredArgsConstructor
public class RefreshTokenHookController {
    public static final String TOKEN_REFRESH_REQUEST_MAPPING = "/token/refresh";
    private final HydraService hydraService;
    private final SsoConfigurationProperties ssoConfigurationProperties;

    @PostMapping(TOKEN_REFRESH_REQUEST_MAPPING)
    public ResponseEntity<RefreshTokenHookResponse> tokenRefresh(@RequestBody RefreshTokenHookRequest request) throws ParseException {
        // TODO: Needs hydra 1.11.9 for session and requester fields;
        log.debug("Token refresh request received: {}", request);

        String sessionId = request.getSessionId();
        if (sessionId == null) {
            return ResponseEntity.status(FORBIDDEN).build();
        }

        List<Consent> consents = hydraService.getConsents(request.getSubject(), sessionId);
        JWT idToken = hydraService.getTaraIdTokenFromConsentContext(consents);
        if (idToken == null) {
            return ResponseEntity.status(FORBIDDEN).build();
        } else if (!isValidRequestIdToken(request, idToken)) {
            return ResponseEntity.status(FORBIDDEN).build();
        }

        JWTClaimsSet idTokenClaims = idToken.getJWTClaimsSet();
        RefreshTokenHookResponseBuilder responseBuilder = RefreshTokenHookResponse.builder()
                .sessionId(sessionId)
                .refreshRememberFor(true)
                .rememberFor(ssoConfigurationProperties.getSessionMaxUpdateIntervalSeconds())
                .refreshConsentRememberFor(true)
                .consentRememberFor(ssoConfigurationProperties.getSessionMaxUpdateIntervalSeconds());
        if (idTokenClaims.getClaims().get("profile_attributes") instanceof Map profileAttributes) {
            responseBuilder
                    .givenName(profileAttributes.get("given_name").toString())
                    .familyName(profileAttributes.get("family_name").toString())
                    .birthDate(profileAttributes.get("date_of_birth").toString());
        }

        RefreshTokenHookResponse response = responseBuilder.build();
        log.debug("Token refresh response: {}", response);
        return ResponseEntity.ok(response);
    }

    private boolean isValidRequestIdToken(RefreshTokenHookRequest request, JWT idToken) throws ParseException {
        String idTokenAcr = idToken.getJWTClaimsSet().getStringClaim("acr");
        IdToken requestIdToken = request.getSession().getIdToken();
        String requestIdTokenAcr = requestIdToken.getIdTokenClaims().getAcr();

        return LevelOfAssurance.findByAcrName(idTokenAcr).getAcrLevel()
                >= LevelOfAssurance.findByAcrName(requestIdTokenAcr).getAcrLevel();
    }

    @ExceptionHandler({Exception.class})
    public ResponseEntity<Object> handleAnyException(Exception ex) {
        log.error("Exception occurred during token refresh request", ex);
        return ResponseEntity.status(FORBIDDEN).build();
    }
}
