package ee.ria.govsso.session.services;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

@Slf4j
@Service
@RequiredArgsConstructor
public class TaraService {

    private final WebClient webclient;
    private final TaraConfigurationProperties taraConfigurationProperties;

    public String getIdToken(String code, String redirectUri) {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "authorization_code");
        formData.add("code", code);
        formData.add("redirect_uri", redirectUri);

        TokenResponse tokenResponse = webclient.post()
                .uri(taraConfigurationProperties.getTokenUrl().toString())
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .headers(headers -> headers.setBasicAuth(
                        taraConfigurationProperties.getClientId(),
                        taraConfigurationProperties.getClientSecret()))
                .body(BodyInserters.fromFormData(formData))
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .block();

        return tokenResponse.getIdToken();
    }

    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class TokenResponse {

        private String idToken;
    }
}
