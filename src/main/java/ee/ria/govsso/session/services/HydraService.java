package ee.ria.govsso.session.services;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import lombok.Data;
import lombok.RequiredArgsConstructor;
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

    public String acceptLogin(String loginChallenge, String sub) throws JsonProcessingException {
        String uri = hydraConfigurationProperties.getAdminUrl() + "/oauth2/auth/requests/login/accept";
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri)
                .queryParam("login_challenge", loginChallenge);

        LoginAcceptRequestBody requestBody = new LoginAcceptRequestBody(false, "high", sub);

        LoginAcceptResponseBody acceptResponseBody = webclient.put()
                .uri(builder.toUriString())
                .contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(requestBody))
                .retrieve()
                .bodyToMono(LoginAcceptResponseBody.class)
                .block();

        return acceptResponseBody.getRedirectUrl();
    }

    @Data
    static class LoginAcceptRequestBody {

        private final boolean remember;
        private final String acr;
        private final String subject;
    }

    @Data
    static class LoginAcceptResponseBody {

        @JsonProperty("redirect_to")
        private String redirectUrl;
    }
}
