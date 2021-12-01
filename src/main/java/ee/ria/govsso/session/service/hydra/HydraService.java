package ee.ria.govsso.session.service.hydra;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
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

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class HydraService {

    private final WebClient webclient;
    private final HydraConfigurationProperties hydraConfigurationProperties;

    public SsoSession.LoginRequestInfo fetchLoginRequestInfo(String loginChallenge) {
        String uri = hydraConfigurationProperties.getAdminUrl() + "/oauth2/auth/requests/login";
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri)
                .queryParam("login_challenge", loginChallenge);

        try {
            SsoSession.LoginRequestInfo loginRequestInfo = webclient.get()
                    .uri(builder.toUriString())
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToMono(SsoSession.LoginRequestInfo.class)
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
    public String acceptLogin(String loginChallenge, JWT idToken) {
        String uri = hydraConfigurationProperties.getAdminUrl() + "/oauth2/auth/requests/login/accept";
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri)
                .queryParam("login_challenge", loginChallenge);

        JWTClaimsSet jwtClaimsSet = idToken.getJWTClaimsSet();
        LoginAcceptRequestBody requestBody = new LoginAcceptRequestBody(false, "high", jwtClaimsSet.getSubject());

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
}
