package ee.ria.govsso.session.service.hydra;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.govsso.session.common.ClientRequestMetadata;
import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.ClientRequestLogger;
import ee.ria.govsso.session.token.AccessTokenClaimsFactory;
import ee.ria.govsso.session.token.UserAttributes;
import ee.ria.govsso.session.util.SecureAppUtil;
import lombok.NonNull;
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
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import static ee.ria.govsso.session.service.helper.ClientScopes.SCOPE_PHONE;
import static java.util.stream.Collectors.toSet;

@Service
@RequiredArgsConstructor
public class HydraService {

    public static final String SESSION_EXPIRY_CLAIM = "session_expiry";

    @Qualifier("hydraWebClient")
    private final WebClient webclient;
    @Qualifier("hydraRequestLogger")
    private final ClientRequestLogger requestLogger;
    private final AccessTokenClaimsFactory accessTokenClaimsFactory;
    private final HydraConfigurationProperties hydraConfigurationProperties;
    private final SsoConfigurationProperties ssoConfigurationProperties;

    public LoginRequestInfo fetchLoginRequestInfo(String loginChallenge) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/admin/oauth2/auth/requests/login")
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
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/admin/oauth2/auth/requests/logout")
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
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/admin/oauth2/auth/requests/consent")
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

    public Integer getUserSessionCount(String subject) {
        List<Consent> consents = getConsentsIncludingPartiallyExpired(subject);
        return consents.stream()
                .map(c -> c.getConsentRequest().getLoginSessionId())
                .collect(toSet())
                .size();
    }

    public List<Consent> getValidConsentsAtRequestTime(String subject, String sessionId, @NonNull OffsetDateTime validAt) {
        List<Consent> consents = getConsents(subject, sessionId, IncludeExpiredStrategy.ALL_EXPIRED)
                .stream()
                .filter(c -> c.isValidAt(validAt))
                .toList();
        validateContextTokens(consents);
        return consents;
    }

    public List<Consent> getValidConsents(String subject, String sessionId) {
        List<Consent> consents = getConsents(subject, sessionId, IncludeExpiredStrategy.ALL_ACTIVE);
        validateContextTokens(consents);
        return consents;
    }

    private static void validateContextTokens(List<Consent> consents) {
        if (consents.isEmpty()) {
            return;
        }
        Context context = consents.get(0).getConsentRequest().getContext();
        boolean allIdentical = consents.stream()
                .map(c -> c.getConsentRequest().getContext())
                .allMatch(c -> Objects.equals(c.getTaraIdToken(), context.getTaraIdToken())
                        && Objects.equals(c.getAuthHandoverToken(), context.getAuthHandoverToken()));
        if (!allIdentical) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Valid consents did not have identical session token values");
        }
    }

    public List<Consent> getConsentsIncludingPartiallyExpired(String subject) {
        return getConsents(subject, null, IncludeExpiredStrategy.PARTIALLY_EXPIRED);
    }

    private List<Consent> getConsents(String subject, String sessionId, IncludeExpiredStrategy includeExpiredStrategy) {
        UriComponentsBuilder uriBuilder = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/admin/oauth2/auth/sessions/consent")
                .queryParam("subject", subject);
        if (includeExpiredStrategy != IncludeExpiredStrategy.ALL_ACTIVE) {
            uriBuilder.queryParam("include_expired", includeExpiredStrategy.name().toLowerCase());
        }
        if (sessionId != null) {
            uriBuilder.queryParam("login_session_id", sessionId);
        }
        String uri = uriBuilder.toUriString();

        try {
            requestLogger.logRequest(uri, HttpMethod.GET.name());
            List<Consent> consents = webclient.get()
                    .uri(uri)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToFlux(Consent.class)
                    .collectList()
                    .blockOptional().orElseThrow();

            requestLogger.logResponse(HttpStatus.OK.value(), consents);
            return consents;
        } catch (WebClientResponseException ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to fetch Hydra consents list", ex);
        }
    }

    public JWT getTaraIdTokenFromConsentContext(List<Consent> consents) {
        if (consents.isEmpty()) {
            return null;
        }
        try {
            JWT idToken = SignedJWT.parse(consents.get(0).getConsentRequest().getContext().getTaraIdToken());
            // TODO: Verifying that session max lifetime has not elapsed should not be done when extracting TARA
            //  ID token.
            validateSessionMaxAgeNotReached(consents);
            return idToken;
        } catch (ParseException ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Unable to parse ID token", ex);
        }
    }

    @SneakyThrows
    public UserAttributes getUserAttributesFromConsentContext(List<Consent> consents) {
        if (consents.isEmpty()) {
            return null;
        }
        validateSessionMaxAgeNotReached(consents);
        return extractUserAttributes(consents.get(0).getConsentRequest().getContext());
    }

    @SneakyThrows
    public LoginAcceptResponse acceptSecuredAppWebSessionLogin(JWT authHandoverToken, LoginRequestInfo loginRequestInfo, ClientRequestMetadata metadata) {
        Context context = createContext(metadata, SessionType.SECURED_APP_WEB_SESSION);
        context.setAuthHandoverToken(authHandoverToken.getParsedString());
        Duration rememberFor = ssoConfigurationProperties.getSessionMaxUpdateInterval();
        LoginAcceptRequest request = createLoginAcceptRequest(authHandoverToken, context, rememberFor);

        String loginChallenge = loginRequestInfo.getChallenge();
        return getLoginAcceptResponse(request, loginChallenge);
    }

    @SneakyThrows
    public LoginAcceptResponse acceptLogin(JWT taraIdToken, LoginRequestInfo loginRequestInfo,
                                           ClientRequestMetadata metadata) {
        Client client = loginRequestInfo.getClient();
        boolean isLongLivingSession = client.isSecuredApp();
        SessionType sessionType = isLongLivingSession ?
                SessionType.SECURED_APP_SESSION :
                SessionType.WEB_SESSION;

        Context context = createContext(metadata, sessionType);
        context.setTaraIdToken(taraIdToken.getParsedString());
        Duration rememberFor = isLongLivingSession ?
                client.getLongLivedSessionLifetime() :
                ssoConfigurationProperties.getSessionMaxUpdateInterval();
        LoginAcceptRequest request = createLoginAcceptRequest(taraIdToken, context, rememberFor);

        String loginChallenge = loginRequestInfo.getChallenge();
        return getLoginAcceptResponse(request, loginChallenge);
    }

    private Context createContext(ClientRequestMetadata metadata, SessionType sessionType) {
        Context context = new Context();
        context.setIpAddress(metadata.ipAddress());
        context.setUserAgent(metadata.userAgent());
        context.setIpCountry(metadata.ipCountry());
        context.setLongLivingSession(sessionType == SessionType.SECURED_APP_SESSION);
        context.setSessionType(sessionType);
        return context;
    }

    private LoginAcceptRequest createLoginAcceptRequest(JWT token, Context context, Duration rememberFor) throws ParseException {
        JWTClaimsSet jwtClaimsSet = token.getJWTClaimsSet();
        LoginAcceptRequest request = new LoginAcceptRequest();
        request.setRemember(true);
        request.setAcr(jwtClaimsSet.getStringClaim("acr"));
        request.setSubject(jwtClaimsSet.getSubject());
        request.setContext(context);
        request.setRememberFor(Math.toIntExact(rememberFor.toSeconds()));
        request.setAmr(jwtClaimsSet.getStringArrayClaim("amr"));
        request.setExtendSessionLifespan(true);
        return request;
    }

    private LoginAcceptResponse getLoginAcceptResponse(LoginAcceptRequest request, String loginChallenge) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/admin/oauth2/auth/requests/login/accept")
                .queryParam("login_challenge", loginChallenge)
                .toUriString();
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
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/admin/oauth2/auth/requests/logout/accept")
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
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/admin/oauth2/auth/requests/logout/reject")
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
    public ConsentAcceptResponse acceptConsent(String consentChallenge, ConsentRequestInfo consentRequestInfo, RepresenteeList representeeList) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/admin/oauth2/auth/requests/consent/accept")
                .queryParam("consent_challenge", consentChallenge)
                .toUriString();

        ConsentAcceptRequest request = new ConsentAcceptRequest();
        ConsentAcceptRequest.LoginSession session = new ConsentAcceptRequest.LoginSession();
        ConsentAcceptRequest.IdToken idToken = new ConsentAcceptRequest.IdToken();

        List<String> scopes = Arrays.asList(consentRequestInfo.getRequestedScope());
        request.setGrantScope(scopes);
        request.setRemember(true);

        Duration consentFlowDuration = Duration.between(consentRequestInfo.getRequestedAt(), OffsetDateTime.now());
        boolean isLongLivingSession = SecureAppUtil.isSecuredAppSession(consentRequestInfo);
        int rememberFor = isLongLivingSession ?
                Consent.REMEMBER_FOR_FOREVER :
                Math.toIntExact(
                        ssoConfigurationProperties.getSessionMaxUpdateInterval().toSeconds() +
                        consentFlowDuration.getSeconds());
        request.setRememberFor(rememberFor);

        UserAttributes userAttributes = extractUserAttributes(consentRequestInfo.getContext());

        String[] requestedScopes = consentRequestInfo.getRequestedScope();

        idToken.setGivenName(userAttributes.givenName());
        idToken.setFamilyName(userAttributes.familyName());
        idToken.setBirthdate(userAttributes.birthdate());
        idToken.setInitiator(isLongLivingSession ? ClientType.SECURED_APP : null);
        if (List.of(requestedScopes).contains(SCOPE_PHONE) && userAttributes.phoneNumber() != null) {
            idToken.setPhoneNumber(userAttributes.phoneNumber());
            idToken.setPhoneNumberVerified(userAttributes.phoneNumberVerified());
        }
        if (representeeList != null) {
            idToken.setRepresenteeList(representeeList);
        }
        session.setIdToken(idToken);

        if (AccessTokenStrategy.JWT.equals(consentRequestInfo.getClient().getAccessTokenStrategy())) {
            session.setAccessToken(accessTokenClaimsFactory.from(userAttributes, List.of(requestedScopes), isLongLivingSession, consentRequestInfo.getAuthenticatedAt().toInstant()));
            if (consentRequestInfo.getRequestedAccessTokenAudience() != null) {
                List<String> audiences = Arrays.asList(consentRequestInfo.getRequestedAccessTokenAudience());
                if (audiences.isEmpty()) {
                    request.setGrantAccessTokenAudience(consentRequestInfo.getClient().getAudience());
                } else {
                    request.setGrantAccessTokenAudience(audiences);
                }
            }
        }

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

    private UserAttributes extractUserAttributes(Context context) throws ParseException {
        SessionType sessionType = context.getSessionTypeOrFallback();
        JWTClaimsSet claims;
        return switch (sessionType) {
            case SECURED_APP_WEB_SESSION -> {
                claims = parseRequiredContextToken(context.getAuthHandoverToken(), "an auth handover token");
                yield UserAttributes.fromAuthHandoverToken(claims);
            }
            case WEB_SESSION, SECURED_APP_SESSION -> {
                claims = parseRequiredContextToken(context.getTaraIdToken(), "a TARA ID token");
                yield UserAttributes.fromTaraIdToken(claims);
            }
        };
    }

    private JWTClaimsSet parseRequiredContextToken(String token, String tokenDescription) throws ParseException {
        Objects.requireNonNull(token, "Session context does not contain %s".formatted(tokenDescription));
        return SignedJWT.parse(token).getJWTClaimsSet();
    }

    public void deleteConsentBySubject(String subject) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/admin/oauth2/auth/sessions/consent")
                .queryParam("subject", subject)
                .queryParam("all", true)
                .queryParam("trigger_backchannel_logout", true)
                .toUriString();
        handleConsentRequest(uri, HttpMethod.DELETE);
    }

    public void expireConsentByClientSession(String clientId, String subject, String loginSessionId) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/admin/oauth2/auth/sessions/consent")
                .queryParam("client", clientId)
                .queryParam("subject", subject)
                .queryParam("login_session_id", loginSessionId)
                .queryParam("all", false)
                .queryParam("trigger_backchannel_logout", true)
                .toUriString();
        handleConsentRequest(uri, HttpMethod.PUT);
    }

    public void deleteConsentBySubjectSession(String subject, String loginSessionId) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/admin/oauth2/auth/sessions/consent")
                .queryParam("subject", subject)
                .queryParam("login_session_id", loginSessionId)
                .queryParam("all", true)
                .queryParam("trigger_backchannel_logout", true)
                .toUriString();
        handleConsentRequest(uri, HttpMethod.DELETE);
    }

    private void handleConsentRequest(String uri, HttpMethod method) {
        try {
            requestLogger.logRequest(uri, method.name());
            ResponseEntity<Void> responseEntity = webclient.method(method)
                    .uri(uri)
                    .retrieve()
                    .toBodilessEntity()
                    .blockOptional().orElseThrow();

            requestLogger.logResponse(HttpStatus.OK.value(), responseEntity);
        } catch (Exception ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to %s Hydra consent".formatted(method == HttpMethod.DELETE ? "delete" : "expire"), ex);
        }
    }

    public void deleteLoginSessionAndRelatedLoginRequests(String loginSessionId) {
        String uri = UriComponentsBuilder
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/admin/oauth2/auth/sessions/login")
                .queryParam("sid", loginSessionId)
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
                .fromUriString(hydraConfigurationProperties.adminUrl() + "/admin/oauth2/auth/requests/login/reject")
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

    private void validateSessionMaxAgeNotReached(List<Consent> consents) throws ParseException {
        // Max lifetime for long-living sessions is enforced by Hydra and is longer than max lifetime for regular
        // sessions, so we can skip that check for long-living sessions. Max lifetime for long-living sessions is
        // longer than max lifetime of regular sessions anyway.
        if (SecureAppUtil.isSecuredAppSession(consents)) {
            return;
        }
        Context context = consents.get(0).getConsentRequest().getContext();
        if (Instant.now().isAfter(getSessionMaxAgeExpiration(context))) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Hydra session has expired");
        }
    }

    private Instant getSessionMaxAgeExpiration(Context context) throws ParseException {
        SessionType sessionType = context.getSessionTypeOrFallback();
        JWTClaimsSet claims;
        return switch (sessionType) {
            case SECURED_APP_WEB_SESSION -> {
                claims = parseRequiredContextToken(context.getAuthHandoverToken(), "an auth handover token");
                Date sessionExpiry = claims.getDateClaim(SESSION_EXPIRY_CLAIM);
                if (sessionExpiry == null) {
                    throw new SsoException(ErrorCode.TECHNICAL_GENERAL,
                            "Auth handover token does not contain %s claim".formatted(SESSION_EXPIRY_CLAIM));
                }
                yield sessionExpiry.toInstant();
            }
            case WEB_SESSION -> {
                claims = parseRequiredContextToken(context.getTaraIdToken(), "a TARA ID token");
                yield claims.getNotBeforeTime().toInstant().plus(ssoConfigurationProperties.getSessionMaxDuration());
            }
            case SECURED_APP_SESSION -> throw new IllegalStateException(
                    "Session max age expiration is not applicable to %s, its max lifetime is enforced by Hydra".formatted(sessionType));
        };
    }
}
