package ee.ria.govsso.session.service.hydra;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.ClientRequestLogger;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class HydraService {

    @Qualifier("hydraWebClient")
    private final WebClient webclient;
    @Qualifier("hydraRequestLogger")
    private final ClientRequestLogger requestLogger;
    private final HydraConfigurationProperties hydraConfigurationProperties;
    private final SsoConfigurationProperties ssoConfigurationProperties;

    public LoginRequestInfo fetchLoginRequestInfo(String loginChallenge) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/oauth2/auth/requests/login")
                .queryParam("login_challenge", loginChallenge)
                .toUriString();

        try {
            requestLogger.logRequest(uri, HttpMethod.GET.name());
            LoginRequestInfo loginRequestInfo = webclient.get()
                    .uri(uri)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToMono(LoginRequestInfo.class)
                    .blockOptional().orElseThrow();

            requestLogger.logResponse(HttpStatus.OK.value(), loginRequestInfo);
            if (!loginRequestInfo.getChallenge().equals(loginChallenge)) {
                throw new IllegalStateException("Invalid hydra response");
            }
            return loginRequestInfo;
        } catch (WebClientResponseException ex) {
            if (ex.getStatusCode() == HttpStatus.NOT_FOUND)
                throw new SsoException(ErrorCode.USER_INPUT, "Failed to fetch Hydra login request info", ex);
            else if (ex.getStatusCode() == HttpStatus.GONE)
                throw new SsoException(ErrorCode.USER_INPUT, "Failed to fetch Hydra login request info", ex);
            else
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to fetch Hydra login request info", ex);
        }
    }

    public LogoutRequestInfo fetchLogoutRequestInfo(String logoutChallenge) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/oauth2/auth/requests/logout")
                .queryParam("logout_challenge", logoutChallenge)
                .toUriString();

        try {
            requestLogger.logRequest(uri, HttpMethod.GET.name());
            LogoutRequestInfo logoutRequestInfo = webclient.get()
                    .uri(uri)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToMono(LogoutRequestInfo.class)
                    .blockOptional().orElseThrow();

            requestLogger.logResponse(HttpStatus.OK.value(), logoutRequestInfo);
            if (!logoutRequestInfo.getChallenge().equals(logoutChallenge)) {
                throw new IllegalStateException("Invalid hydra response");
            }
            return logoutRequestInfo;
        } catch (WebClientResponseException ex) {
            if (ex.getStatusCode() == HttpStatus.NOT_FOUND || ex.getStatusCode() == HttpStatus.GONE)
                throw new SsoException(ErrorCode.USER_INPUT, "Failed to fetch Hydra logout request info", ex);
            else
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to fetch Hydra logout request info", ex);
        }
    }

    public ConsentRequestInfo fetchConsentRequestInfo(String consentChallenge) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/oauth2/auth/requests/consent")
                .queryParam("consent_challenge", consentChallenge)
                .toUriString();

        try {
            requestLogger.logRequest(uri, HttpMethod.GET.name());
            ConsentRequestInfo consentRequestInfo = webclient.get()
                    .uri(uri)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToMono(ConsentRequestInfo.class)
                    .blockOptional().orElseThrow();

            requestLogger.logResponse(HttpStatus.OK.value(), consentRequestInfo);
            if (!consentRequestInfo.getChallenge().equals(consentChallenge)) {
                throw new IllegalStateException("Invalid hydra response");
            }
            return consentRequestInfo;
        } catch (WebClientResponseException ex) {
            if (ex.getStatusCode() == HttpStatus.NOT_FOUND)
                throw new SsoException(ErrorCode.USER_INPUT, "Failed to fetch Hydra consent request info", ex);
            else if (ex.getStatusCode() == HttpStatus.GONE)
                throw new SsoException(ErrorCode.USER_INPUT, "Failed to fetch Hydra consent request info", ex);
            else
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to fetch Hydra consent request info", ex);
        }
    }

    public List<Consent> getConsents(String subject, String sessionId) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/oauth2/auth/sessions/consent")
                .queryParam("subject", subject)
                .toUriString();

        try {
            requestLogger.logRequest(uri, HttpMethod.GET.name());
            List<Consent> validConsents = webclient.get()
                    .uri(uri)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToFlux(Consent.class)
                    .filter(c -> c.getConsentRequest().getLoginSessionId().equals(sessionId))
                    .collectList()
                    .blockOptional().orElseThrow();

            requestLogger.logResponse(HttpStatus.OK.value(), validConsents);
            if (validConsents.isEmpty()) {
                return Collections.emptyList();
            }

            var taraIdToken = validConsents.get(0).getConsentRequest().getContext().getTaraIdToken();
            if (!validConsents.stream().allMatch(s -> s.getConsentRequest().getContext().getTaraIdToken().equals(taraIdToken))) {
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Valid consents did not have identical tara_id_token values");
            }

            return validConsents;
        } catch (WebClientResponseException ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to fetch Hydra consents list", ex);
        }
    }

    public JWT getTaraIdTokenFromConsentContext(String subject, String sessionId) {
        List<Consent> validConsents = getConsents(subject, sessionId);
        if (validConsents.isEmpty()) {
            return null;
        }
        try {
            JWT idToken = SignedJWT.parse(validConsents.get(0).getConsentRequest().getContext().getTaraIdToken());
            if (!isNbfValid(idToken)) {
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Hydra session has expired");
            }
            return idToken;
        } catch (ParseException ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Unable to parse ID token", ex);
        }
    }

    @SneakyThrows
    public LoginAcceptResponse acceptLogin(String loginChallenge, JWT idToken) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/oauth2/auth/requests/login/accept")
                .queryParam("login_challenge", loginChallenge)
                .toUriString();

        JWTClaimsSet jwtClaimsSet = idToken.getJWTClaimsSet();

        Context context = new Context();
        context.setTaraIdToken(idToken.getParsedString());

        LoginAcceptRequest request = new LoginAcceptRequest();
        request.setRemember(true);
        request.setAcr(jwtClaimsSet.getStringClaim("acr"));
        request.setSubject(jwtClaimsSet.getSubject());
        request.setContext(context);
        request.setRememberFor(ssoConfigurationProperties.getSessionMaxUpdateIntervalSeconds());
        request.setAmr(jwtClaimsSet.getStringArrayClaim("amr"));
        request.setRefreshRememberFor(true);

        requestLogger.logRequest(uri, HttpMethod.PUT.name(), request);
        LoginAcceptResponse response = webclient.put()
                .uri(uri)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(request))
                .retrieve()
                .bodyToMono(LoginAcceptResponse.class)
                .blockOptional().orElseThrow();

        requestLogger.logResponse(HttpStatus.OK.value(), response);
        return response;
    }

    public LogoutAcceptResponse acceptLogout(String logoutChallenge) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/oauth2/auth/requests/logout/accept")
                .queryParam("logout_challenge", logoutChallenge)
                .toUriString();

        try {
            requestLogger.logRequest(uri, HttpMethod.PUT.name());
            LogoutAcceptResponse response = webclient.put()
                    .uri(uri)
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToMono(LogoutAcceptResponse.class)
                    .blockOptional().orElseThrow();

            requestLogger.logResponse(HttpStatus.OK.value(), response);
            return response;
        } catch (WebClientResponseException ex) {
            if (ex.getStatusCode() == HttpStatus.NOT_FOUND)
                throw new SsoException(ErrorCode.USER_INPUT, "Failed to accept Hydra logout request", ex);
            else
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to accept Hydra logout request", ex);
        }
    }

    public void rejectLogout(String logoutChallenge) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/oauth2/auth/requests/logout/reject")
                .queryParam("logout_challenge", logoutChallenge)
                .toUriString();

        try {
            requestLogger.logRequest(uri, HttpMethod.PUT.name());
            ResponseEntity<Void> responseEntity = webclient.put()
                    .uri(uri)
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .toBodilessEntity()
                    .blockOptional().orElseThrow();

            requestLogger.logResponse(HttpStatus.OK.value(), responseEntity);
        } catch (WebClientResponseException ex) {
            if (ex.getStatusCode() == HttpStatus.NOT_FOUND)
                throw new SsoException(ErrorCode.USER_INPUT, "Failed to reject Hydra logout request", ex);
            else
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to reject Hydra logout request", ex);
        }
    }

    @SneakyThrows
    public ConsentAcceptResponse acceptConsent(String consentChallenge, ConsentRequestInfo consentRequestInfo) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/oauth2/auth/requests/consent/accept")
                .queryParam("consent_challenge", consentChallenge)
                .toUriString();

        ConsentAcceptRequest request = new ConsentAcceptRequest();
        ConsentAcceptRequest.LoginSession session = new ConsentAcceptRequest.LoginSession();
        ConsentAcceptRequest.IdToken idToken = new ConsentAcceptRequest.IdToken();

        List<String> scopes = Arrays.asList(consentRequestInfo.getRequestedScope());
        request.setGrantScope(scopes);
        request.setRemember(true);
        request.setRememberFor(ssoConfigurationProperties.getSessionMaxUpdateIntervalSeconds());

        JWT taraIdToken = SignedJWT.parse(consentRequestInfo.getContext().getTaraIdToken());
        Map<String, Object> profileAttributesClaim = taraIdToken.getJWTClaimsSet().getJSONObjectClaim("profile_attributes");

        String[] requestedScopes = consentRequestInfo.getRequestedScope();

        idToken.setGivenName(profileAttributesClaim.get("given_name").toString());
        idToken.setFamilyName(profileAttributesClaim.get("family_name").toString());
        idToken.setBirthdate(profileAttributesClaim.get("date_of_birth").toString());
        if (List.of(requestedScopes).contains("phone") && taraIdToken.getJWTClaimsSet().getClaims().get("phone_number") != null) {
            idToken.setPhoneNumber(taraIdToken.getJWTClaimsSet().getClaims().get("phone_number").toString());
            idToken.setPhoneNumberVerified((Boolean) taraIdToken.getJWTClaimsSet().getClaims().get("phone_number_verified"));
        }
        session.setIdToken(idToken);
        request.setSession(session);

        requestLogger.logRequest(uri, HttpMethod.PUT.name(), request);
        ConsentAcceptResponse response = webclient.put()
                .uri(uri)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(request))
                .retrieve()
                .bodyToMono(ConsentAcceptResponse.class)
                .blockOptional().orElseThrow();

        requestLogger.logResponse(HttpStatus.OK.value(), response);
        return response;
    }

    public void deleteConsentByClientSession(String clientId, String subject, String loginSessionId) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/oauth2/auth/sessions/consent")
                .queryParam("client", clientId)
                .queryParam("subject", subject)
                .queryParam("login_session_id", loginSessionId)
                .queryParam("all", false)
                .queryParam("trigger_backchannel_logout", true)
                .toUriString();
        deleteConsent(uri);
    }

    public void deleteConsentBySubjectSession(String subject, String loginSessionId) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/oauth2/auth/sessions/consent")
                .queryParam("subject", subject)
                .queryParam("login_session_id", loginSessionId)
                .queryParam("all", true)
                .queryParam("trigger_backchannel_logout", true)
                .toUriString();
        deleteConsent(uri);
    }

    private void deleteConsent(String uri) {
        try {
            requestLogger.logRequest(uri, HttpMethod.DELETE.name());
            ResponseEntity<Void> responseEntity = webclient.delete()
                    .uri(uri)
                    .retrieve()
                    .toBodilessEntity()
                    .blockOptional().orElseThrow();

            requestLogger.logResponse(HttpStatus.OK.value(), responseEntity);
        } catch (Exception ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to delete Hydra consent", ex);
        }
    }

    public void deleteLoginSessionAndRelatedLoginRequests(String loginSessionId) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/oauth2/auth/sessions/login/" + loginSessionId)
                .toUriString();

        try {
            requestLogger.logRequest(uri, HttpMethod.DELETE.name());
            ResponseEntity<Void> responseEntity = webclient.delete()
                    .uri(uri)
                    .retrieve()
                    .toBodilessEntity()
                    .blockOptional().orElseThrow();

            requestLogger.logResponse(HttpStatus.OK.value(), responseEntity);
        } catch (Exception ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to delete Hydra login", ex);
        }
    }

    // TODO GSSO-244 Call this on unsuccessful outcome of login flows so that Hydra resource cleanup would be immediate.
    public LoginRejectResponse rejectLogin(String loginChallenge) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/oauth2/auth/requests/login/reject")
                .queryParam("login_challenge", loginChallenge)
                .toUriString();

        try {
            requestLogger.logRequest(uri, HttpMethod.PUT.name());
            LoginRejectResponse response = webclient.put()
                    .uri(uri)
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(BodyInserters.fromValue(new LoginRejectRequest()))
                    .retrieve()
                    .bodyToMono(LoginRejectResponse.class)
                    .blockOptional().orElseThrow();

            requestLogger.logResponse(HttpStatus.OK.value(), response);
            return response;
        } catch (WebClientResponseException ex) {
            if (ex.getStatusCode() == HttpStatus.NOT_FOUND)
                throw new SsoException(ErrorCode.USER_INPUT, "Failed to reject Hydra login request", ex);
            else if (ex.getStatusCode() == HttpStatus.CONFLICT) {
                throw new SsoException(ErrorCode.USER_INPUT, "Failed to reject Hydra login request", ex);
            } else
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to reject Hydra login request", ex);
        }
    }

    private boolean isNbfValid(JWT idToken) throws ParseException {
        Date idTokenDate = idToken.getJWTClaimsSet().getNotBeforeTime();
        Date currentDate = new Date();

        long diffInMillis = Math.abs(currentDate.getTime() - idTokenDate.getTime());
        long diffInSeconds = TimeUnit.SECONDS.convert(diffInMillis, TimeUnit.MILLISECONDS);
        long maxDurationInSeconds = TimeUnit.SECONDS.convert(ssoConfigurationProperties.getSessionMaxDurationHours(), TimeUnit.HOURS);

        return diffInSeconds <= maxDurationInSeconds;
    }
}
