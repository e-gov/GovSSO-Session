package ee.ria.govsso.session.service.tara;

import ch.qos.logback.classic.Logger;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import ee.ria.govsso.session.error.exceptions.SsoException;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static com.nimbusds.oauth2.sdk.GrantType.AUTHORIZATION_CODE;
import static com.nimbusds.oauth2.sdk.ResponseType.CODE;
import static com.nimbusds.openid.connect.sdk.SubjectType.PUBLIC;
import static com.nimbusds.openid.connect.sdk.claims.ClaimType.NORMAL;
import static ee.ria.govsso.session.error.ErrorCode.TECHNICAL_TARA_UNAVAILABLE;
import static java.util.List.of;
import static java.util.stream.Collectors.toList;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.slf4j.Logger.ROOT_LOGGER_NAME;
import static org.slf4j.LoggerFactory.getLogger;

@Slf4j
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestPropertySource(properties = {
        "govsso.tara.metadata-interval=100",
        "govsso.tara.metadata-max-attempts=3",
        "govsso.tara.metadata-backoff-delay-milliseconds=100",
        "govsso.tara.metadata-backoff-multiplier=1.0"})
@RequiredArgsConstructor(onConstructor_ = @Autowired)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class TaraMetadataServiceTest extends BaseTest {

    private final TaraConfigurationProperties taraConfigurationProperties;

    @SpyBean
    private TaraMetadataService taraMetadataService;

    @Value("${govsso.tara.metadata-max-attempts}")
    private Integer metadataUpdateMaxAttempts;

    @BeforeAll
    static void setUpTaraMetadataNotAvailable() {
        TARA_MOCK_SERVER.resetAll();
    }

    @BeforeEach
    public void stopLoggingAppender() {
        // We are not using BaseTestLoggingAssertion.assertErrorIsLogged to assert exceptions, but are directly
        // asserting exceptions thrown by called methods. Because of retry mechanism in TaraMetadataService, same errors
        // are logged multiple times. Logging must be turned off, because otherwise all logged errors and warnings must
        // be asserted in tests.
        ((Logger) getLogger(ROOT_LOGGER_NAME)).detachAndStopAllAppenders();
    }

    @Test
    @Order(1)
    void getMetadata_WhenMetadataNotUpdated_ThrowsSsoException() {
        SsoException ssoException = assertThrows(SsoException.class, taraMetadataService::getMetadata);

        assertThat(ssoException.getErrorCode(), equalTo(TECHNICAL_TARA_UNAVAILABLE));
        assertThat(ssoException.getMessage(), equalTo("TARA metadata not available"));
    }

    @Test
    @Order(2)
    void getIDTokenValidator_WhenMetadataNotUpdated_ThrowsSsoException() {
        SsoException ssoException = assertThrows(SsoException.class, taraMetadataService::getIDTokenValidator);

        assertThat(ssoException.getErrorCode(), equalTo(TECHNICAL_TARA_UNAVAILABLE));
        assertThat(ssoException.getMessage(), equalTo("TARA metadata not available"));
    }

    @Test
    @Order(3)
    @SneakyThrows
    void updateMetadata_WhenTaraMetadataNotAvailable_RetriesMetadataRequest() {
        setUpMetadataNotAvailable();
        int nextScheduledInvocationCall = metadataUpdateMaxAttempts + 1;

        await().atMost(FIVE_SECONDS)
                .untilAsserted(() -> verify(taraMetadataService, atLeast(nextScheduledInvocationCall)).updateMetadata());

        verify(taraMetadataService, atLeast(nextScheduledInvocationCall)).requestMetadata();
        verify(taraMetadataService, never()).requestJWKSet(any());
        SsoException exceptionFromGetMetadata = assertThrows(SsoException.class, taraMetadataService::getMetadata);
        SsoException exceptionFromGetIDTokenValidator = assertThrows(SsoException.class, taraMetadataService::getIDTokenValidator);
        assertThat(exceptionFromGetMetadata.getErrorCode(), equalTo(TECHNICAL_TARA_UNAVAILABLE));
        assertThat(exceptionFromGetMetadata.getMessage(), equalTo("TARA metadata not available"));
        assertThat(exceptionFromGetIDTokenValidator.getErrorCode(), equalTo(TECHNICAL_TARA_UNAVAILABLE));
        assertThat(exceptionFromGetIDTokenValidator.getMessage(), equalTo("TARA metadata not available"));
    }

    // TODO: flaky test
    @Test
    @Order(4)
    @SneakyThrows
    void updateMetadata_WhenTaraJwkSetNotAvailable_RetriesMetadataRequest() {
        setUpMetadataWithoutJwkSet();
        int nextScheduledInvocationCall = metadataUpdateMaxAttempts + 1;

        await().atMost(FIVE_SECONDS)
                .untilAsserted(() -> verify(taraMetadataService, atLeast(nextScheduledInvocationCall)).updateMetadata());

        verify(taraMetadataService, atLeast(metadataUpdateMaxAttempts)).requestMetadata();
        verify(taraMetadataService, atLeast(metadataUpdateMaxAttempts)).requestJWKSet(any());
        verify(taraMetadataService, never()).createIdTokenValidator(any(), any());
        SsoException exceptionFromGetMetadata = assertThrows(SsoException.class, taraMetadataService::getMetadata);
        SsoException exceptionFromGetIDTokenValidator = assertThrows(SsoException.class, taraMetadataService::getIDTokenValidator);

        assertThat(exceptionFromGetMetadata.getErrorCode(), equalTo(TECHNICAL_TARA_UNAVAILABLE));
        assertThat(exceptionFromGetMetadata.getMessage(), equalTo("TARA metadata not available"));
        assertThat(exceptionFromGetIDTokenValidator.getErrorCode(), equalTo(TECHNICAL_TARA_UNAVAILABLE));
        assertThat(exceptionFromGetIDTokenValidator.getMessage(), equalTo("TARA metadata not available"));
    }

    // TODO: flaky test
    @Test
    @Order(5)
    @SneakyThrows
    void updateMetadata_WhenTaraMetadataAndJwkSetAvailable_SucceedsAndCachesResult() {
        setUpTaraMetadataMocks();

        await().atMost(FIVE_SECONDS)
                .untilAsserted(() -> verify(taraMetadataService, atLeast(1)).createIdTokenValidator(any(), any()));

        verify(taraMetadataService, atLeast(1)).requestMetadata();
        verify(taraMetadataService, atLeast(1)).requestJWKSet(any());
        verify(taraMetadataService, atLeast(1)).createIdTokenValidator(any(), any());
        OIDCProviderMetadata metadata = taraMetadataService.getMetadata();
        assertThat(metadata.getIssuer().getValue(), equalTo(taraConfigurationProperties.issuerUrl().toString()));
        assertThat(metadata.getTokenEndpointURI().toString(), equalTo(TARA_MOCK_URL + "/oidc/token"));
        assertThat(metadata.getAuthorizationEndpointURI().toString(), equalTo(TARA_MOCK_URL + "/oidc/authorize"));
        assertThat(metadata.getJWKSetURI().toString(), equalTo(TARA_MOCK_URL + "/oidc/jwks"));
        assertThat(metadata.getTokenEndpointAuthMethods(), equalTo(of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)));
        assertThat(metadata.getSubjectTypes(), contains(PUBLIC));
        assertThat(metadata.getResponseTypes(), contains(CODE));
        assertThat(metadata.getGrantTypes(), contains(AUTHORIZATION_CODE));
        assertThat(metadata.getIDTokenJWSAlgs(), contains(RS256));
        assertThat(metadata.getUILocales(), contains(LangTag.parse("et"), LangTag.parse("en"), LangTag.parse("ru")));
        assertThat(metadata.getClaimTypes(), contains(NORMAL));
        assertThat(metadata.getClaims(), contains(
                "sub",
                "email",
                "email_verified",
                "phonenumber",
                "phonenumber_verified",
                "given_name",
                "family_name",
                "date_of_birth",
                "represents_legal_person.name",
                "represents_legal_person.registry_code"));
        assertThat(metadata.getScopes().stream().map(Identifier::getValue).collect(toList()), contains(
                "openid",
                "idcard",
                "mid",
                "smartid",
                "email",
                "phone",
                "eidas",
                "eidasonly",
                "eidas:country:es",
                "eidas:country:de",
                "eidas:country:it",
                "eidas:country:be",
                "eidas:country:lu",
                "eidas:country:hr",
                "eidas:country:lv",
                "eidas:country:pt",
                "eidas:country:lt",
                "eidas:country:nl",
                "eidas:country:cz",
                "eidas:country:sk",
                "eidas:country:pl"));
        IDTokenValidator idTokenValidator = taraMetadataService.getIDTokenValidator();
        assertThat(idTokenValidator.getClientID().getValue(), equalTo(taraConfigurationProperties.clientId()));
        assertThat(idTokenValidator.getExpectedIssuer().getValue(), equalTo(taraConfigurationProperties.issuerUrl().toString()));
        assertThat(idTokenValidator.getMaxClockSkew(), equalTo(taraConfigurationProperties.maxClockSkewSeconds()));
    }

    @Test
    void updateMetadata_WhenInvalidIssuer_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_invalid_issuer.json");

        assertCauseMessage("Expected OIDC Issuer 'https://tara.localhost:10000' does not match published issuer 'https://tara.localhost:10000/'");
    }

    @Test
    void updateMetadata_WhenMissingJwksUri_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_jwks_uri.json");

        assertCauseMessage("The public JWK set URI must not be null");
    }

    @Test
    void updateMetadata_WhenMissingAuthorizationEndpoint_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_authorization_endpoint.json");

        assertCauseMessage("The public authorization endpoint URI must not be null");
    }

    @Test
    void updateMetadata_WhenBlankAuthorizationEndpoint_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_blank_authorization_endpoint.json");

        assertCauseMessage("The public authorization endpoint URI must not be null");
    }

    @Test
    void updateMetadata_WhenMissingTokenEndpoint_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_token_endpoint.json");

        assertCauseMessage("The public token endpoint URI must not be null");
    }

    @Test
    void updateMetadata_WhenBlankTokenEndpoint_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_blank_token_endpoint.json");

        assertCauseMessage("The public token endpoint URI must not be null");
    }

    @Test
    void updateMetadata_WhenMissingSubjectTypePublic_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_subject_type_public.json");

        assertCauseMessage("Metadata subject types must contain only 'public'");
    }

    @Test
    void updateMetadata_WhenMissingSubjectTypes_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_subject_types.json");

        assertCauseMessage("Missing JSON object member with key subject_types_supported");
    }

    @Test
    void updateMetadata_WhenTooManySubjectTypes_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_too_many_subject_types.json");

        assertCauseMessage("Metadata subject types must contain only 'public'");
    }

    @Test
    void updateMetadata_WhenMissingResponseTypeCode_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_response_type_code.json");

        assertCauseMessage("Metadata response types can not be null and must contain only 'code'");
    }

    @Test
    void updateMetadata_WhenMissingResponseTypes_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_response_types.json");

        assertCauseMessage("Metadata response types can not be null and must contain only 'code'");
    }

    @Test
    void updateMetadata_WhenTooManyResponseTypes_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_too_many_response_types.json");

        assertCauseMessage("Metadata response types can not be null and must contain only 'code'");
    }

    @Test
    void updateMetadata_WhenMissingClaimSub_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_claim_sub.json");

        assertCauseMessage("Metadata claims can not be null and must contain: 'sub'");
    }

    @Test
    void updateMetadata_WhenMissingClaims_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_claims.json");

        assertCauseMessage("Metadata claims can not be null and must contain: 'sub'");
    }

    @Test
    void updateMetadata_WhenMissingGrantTypeAuthorizationCode_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_grant_type_authorization_code.json");

        assertCauseMessage("Metadata grant types can not be null and must contain: 'authorization_code'");
    }

    @Test
    void updateMetadata_WhenMissingGrantTypes_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_grant_types.json");

        assertCauseMessage("Metadata grant types can not be null and must contain: 'authorization_code'");
    }

    @Test
    void updateMetadata_WhenMissingIdTokenJwsAlgRS256_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_id_token_jws_alg_RS256.json");

        assertCauseMessage("Metadata ID token JWS algorithms can not be null and must contain only 'RS256'");
    }

    @Test
    void updateMetadata_WhenMissingIdTokenJwsAlgs_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_id_token_jws_algs.json");

        assertCauseMessage("Metadata ID token JWS algorithms can not be null and must contain only 'RS256'");
    }

    @Test
    void updateMetadata_WhenTooManyIdTokenJwsAlgs_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_too_many_id_token_jws_algs.json");

        assertCauseMessage("Metadata ID token JWS algorithms can not be null and must contain only 'RS256'");
    }

    @Test
    void updateMetadata_WhenMissingClaimTypeNormal_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_claim_type_normal.json");

        assertCauseMessage("Metadata claim types can not be null and must contain only 'normal'");
    }

    @Test
    void updateMetadata_WhenMissingClaimTypes_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_claim_types.json");

        assertCauseMessage("Metadata claim types can not be null and must contain only 'normal'");
    }

    @Test
    void updateMetadata_WhenTooManyClaimTypes_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_too_many_claim_types.json");

        assertCauseMessage("Metadata claim types can not be null and must contain only 'normal'");
    }

    @Test
    void updateMetadata_WhenMissingTokenEndpointAuthMethodClientSecretBasic_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_token_endpoint_auth_method_client_secret_basic.json");

        assertCauseMessage("Metadata token endpoint auth methods can not be null and must contain 'client_secret_basic'");
    }

    @Test
    void updateMetadata_WhenMissingTokenEndpointAuthMethods_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_token_endpoint_auth_methods.json");

        assertCauseMessage("Metadata token endpoint auth methods can not be null and must contain 'client_secret_basic'");
    }

    @Test
    void updateMetadata_WhenMissingScopeOpenid_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_scope_openid.json");

        assertCauseMessage("Metadata scopes can not be null and must contain 'openid'");
    }

    @Test
    void updateMetadata_WhenMissingScopes_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_scopes.json");

        assertCauseMessage("Metadata scopes can not be null and must contain 'openid'");
    }

    private void assertCauseMessage(String causeMessage) {
        SsoException exception = assertThrows(SsoException.class, () -> taraMetadataService.updateMetadata());
        assertThat(exception.getMessage(), equalTo("Unable to update TARA metadata"));
        Throwable cause = exception.getCause();
        assertThat(cause.getMessage(), equalTo(causeMessage));
    }

    private void setUpMetadataWithoutJwkSet() {
        TARA_MOCK_SERVER.stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_tara_oidc_metadata.json")));

        TARA_MOCK_SERVER.stubFor(get(urlEqualTo("/oidc/jwks"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(404)));
    }

    private void setUpMetadataNotAvailable() {
        TARA_MOCK_SERVER.stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(404)));

        TARA_MOCK_SERVER.stubFor(get(urlEqualTo("/oidc/jwks"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(404)));
    }
}
