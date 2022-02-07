package ee.ria.govsso.session.service.tara;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import lombok.SneakyThrows;

import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static java.util.List.of;

public abstract class TaraTestSetup {

    @SneakyThrows
    public static RSAKey generateJWK() {
        return new RSAKeyGenerator(4096)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
    }

    public static void setUpMetadataMocks(WireMockServer wireMockServer, String metadataBodyFile, RSAKey taraJWK) {
        JWKSet jwkSet = new JWKSet(of(taraJWK));

        wireMockServer.stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/" + metadataBodyFile)));

        wireMockServer.stubFor(get(urlEqualTo("/oidc/jwks"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(jwkSet.toPublicJWKSet().toString())));
    }
}
