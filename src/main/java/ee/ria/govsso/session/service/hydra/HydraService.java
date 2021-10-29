package ee.ria.govsso.session.service.hydra;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import ee.ria.govsso.session.session.SsoSession;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

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

        SsoSession.LoginRequestInfo loginRequestInfo = webclient.get()
                .uri(builder.toUriString())
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(SsoSession.LoginRequestInfo.class)
                .blockOptional().orElseThrow();

        if (!loginRequestInfo.getChallenge().equals(loginChallenge))
            throw new IllegalStateException("Invalid hydra response");
        return loginRequestInfo;
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