package ee.ria.govsso.session.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import ee.ria.govsso.session.session.SsoSession;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
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
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .retrieve()
                .bodyToMono(SsoSession.LoginRequestInfo.class)
                .block();

        if (loginRequestInfo == null || !loginRequestInfo.getChallenge().equals(loginChallenge))
            throw new IllegalStateException("Invalid hydra response");
        return loginRequestInfo;
    }

    public String acceptLogin(String loginChallenge, String sub) throws JsonProcessingException {
        String uri = hydraConfigurationProperties.getAdminUrl() + "/oauth2/auth/requests/login/accept";
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri)
                .queryParam("login_challenge", loginChallenge);

        LoginAcceptRequestBody requestBody = new LoginAcceptRequestBody(false, "high", sub);

        LoginAcceptResponseBody acceptResponseBody = webclient.put()
                .uri(builder.toUriString())
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(requestBody))
                .retrieve()
                .bodyToMono(LoginAcceptResponseBody.class)
                .block();

        return acceptResponseBody.getRedirectTo();
    }

    @Data
    static class LoginAcceptRequestBody {

        private final boolean remember;
        private final String acr;
        private final String subject;
    }

    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class LoginAcceptResponseBody {

        private String redirectTo;
    }
}
