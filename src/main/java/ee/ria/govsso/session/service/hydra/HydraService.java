package ee.ria.govsso.session.service.hydra;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.session.SsoSession;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class HydraService {

    private final WebClient webclient;
    private final HydraConfigurationProperties hydraConfigurationProperties;
    private final SsoConfigurationProperties ssoConfigurationProperties;

    public LoginRequestInfo fetchLoginRequestInfo(String loginChallenge) {
        String uri = hydraConfigurationProperties.getAdminUrl() + "/oauth2/auth/requests/login";
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri)
                .queryParam("login_challenge", loginChallenge);

        try {
            LoginRequestInfo loginRequestInfo = webclient.get()
                    .uri(builder.toUriString())
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToMono(LoginRequestInfo.class)
                    .blockOptional().orElseThrow();

            if (!loginRequestInfo.getChallenge().equals(loginChallenge))
                throw new IllegalStateException("Invalid hydra response");
            return loginRequestInfo;
        } catch (WebClientResponseException ex) {
            if (ex.getStatusCode() == HttpStatus.NOT_FOUND)
                throw new SsoException(ErrorCode.USER_INPUT, ex.getMessage(), ex);
            else if (ex.getStatusCode() == HttpStatus.GONE)
                throw new SsoException(ErrorCode.USER_INPUT, ex.getMessage(), ex);
            else
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, ex.getMessage(), ex);
        }
    }

    @SneakyThrows
    public JWT getConsents(String subject, String sessionId) {
        String uri = hydraConfigurationProperties.getAdminUrl() + "/oauth2/auth/sessions/consent";
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri)
                .queryParam("subject", subject);

        Consent[] consents = webclient.get()
                .uri(builder.toUriString())
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(Consent[].class)
                .blockOptional().orElseThrow();

        List<Consent> validConsents = new ArrayList<>();

        for (Consent consent : consents) {
            if (consent.getConsentRequest().getLoginSessionId().equals(sessionId))
                validConsents.add(consent);
        }

        if (validConsents.isEmpty())
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "No valid consent requests found");
        else if (!validConsents.stream().allMatch(s -> s.getConsentRequest().getContext().getTaraIdToken().equals(validConsents.get(0).getConsentRequest().getContext().getTaraIdToken()))) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Valid consents did not have identical tara_id_token values");
        }

        JWT idToken = SignedJWT.parse(validConsents.get(0).getConsentRequest().getContext().getTaraIdToken());

        if (!isNbfValid(idToken))
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Hydra session has expired");

        return idToken;
    }

    @SneakyThrows
    public String acceptLogin(String loginChallenge, JWT idToken) {
        String uri = hydraConfigurationProperties.getAdminUrl() + "/oauth2/auth/requests/login/accept";
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri)
                .queryParam("login_challenge", loginChallenge);

        JWTClaimsSet jwtClaimsSet = idToken.getJWTClaimsSet();

        Context context = new Context();
        context.setTaraIdToken(idToken.getParsedString());

        LoginAcceptRequestBody requestBody = new LoginAcceptRequestBody();
        requestBody.setRemember(true);
        requestBody.setAcr("high");
        requestBody.setSubject(jwtClaimsSet.getSubject());
        requestBody.setContext(context);
        requestBody.setRememberFor(ssoConfigurationProperties.getSessionMaxUpdateIntervalSeconds());
        requestBody.setAmr(jwtClaimsSet.getStringArrayClaim("amr"));
        requestBody.setRefreshRememberFor(true);

        LoginAcceptResponseBody acceptResponseBody = webclient.put()
                .uri(builder.toUriString())
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(requestBody))
                .retrieve()
                .bodyToMono(LoginAcceptResponseBody.class)
                .blockOptional().orElseThrow();

        return acceptResponseBody.getRedirectTo();
    }

    public String acceptConsent(String consentChallenge, SsoSession ssoSession) {
        String uri = hydraConfigurationProperties.getAdminUrl() + "/oauth2/auth/requests/consent/accept";
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri)
                .queryParam("consent_challenge", consentChallenge);

        ConsentAcceptRequestBody requestBody = new ConsentAcceptRequestBody();

        List<String> scopes = List.of("openid");
        requestBody.setGrantScope(scopes);
        requestBody.setRemember(true);
        requestBody.setRememberFor(ssoConfigurationProperties.getSessionMaxUpdateIntervalSeconds());

        ConsentAcceptRequestBody.LoginSession session = new ConsentAcceptRequestBody.LoginSession();
        ConsentAcceptRequestBody.IdToken idToken = new ConsentAcceptRequestBody.IdToken();

        ConsentAcceptRequestBody.ProfileAttributes profileAttributes = new ConsentAcceptRequestBody.ProfileAttributes();
        profileAttributes.setGivenName("Eesnimi");
        profileAttributes.setFamilyName("Perenimi");
        profileAttributes.setDateOfBirth("12.12.2012");

        idToken.setProfileAttributes(profileAttributes);
        session.setIdToken(idToken);
        requestBody.setSession(session);

        ConsentAcceptResponseBody consentResponseBody = webclient.put()
                .uri(builder.toUriString())
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(requestBody))
                .retrieve()
                .bodyToMono(ConsentAcceptResponseBody.class)
                .blockOptional().orElseThrow();

        return consentResponseBody.getRedirectTo();
    }

    public void deleteConsent(String subject, String loginSessionId) {
        String uri = hydraConfigurationProperties.getAdminUrl() + "/oauth2/auth/sessions/consent";
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri)
                .queryParam("subject", subject)
                .queryParam("login_session_id", loginSessionId)
                .queryParam("all", true)
                .queryParam("trigger_backchannel_logout", true);

        try {
            webclient.delete()
                    .uri(builder.toUriString())
                    .retrieve()
                    .toBodilessEntity()
                    .blockOptional().orElseThrow();
        } catch (Exception ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, ex.getMessage(), ex);
        }
    }

    public void deleteLogin(String loginSessionId) {
        String uri = hydraConfigurationProperties.getAdminUrl() + "/oauth2/auth/sessions/login/" + loginSessionId;
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri);

        try {
            webclient.delete()
                    .uri(builder.toUriString())
                    .retrieve()
                    .toBodilessEntity()
                    .blockOptional().orElseThrow();

        } catch (Exception ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, ex.getMessage(), ex);
        }
    }

    public String rejectLogin(String loginChallenge) {
        String uri = hydraConfigurationProperties.getAdminUrl() + "/oauth2/auth/requests/login/reject";
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri)
                .queryParam("login_challenge", loginChallenge);

        try {
            LoginRejectResponseBody loginRejectResponseBody = webclient.put()
                    .uri(builder.toUriString())
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(BodyInserters.fromValue(new LoginRejectRequestBody()))
                    .retrieve()
                    .bodyToMono(LoginRejectResponseBody.class)
                    .blockOptional().orElseThrow();

            return loginRejectResponseBody.getRedirectTo();
        } catch (WebClientResponseException ex) {
            if (ex.getStatusCode() == HttpStatus.NOT_FOUND)
                throw new SsoException(ErrorCode.USER_INPUT, ex.getMessage(), ex);
            else if (ex.getStatusCode() == HttpStatus.CONFLICT)
                return null;
            else
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, ex.getMessage(), ex);
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
