package ee.ria.govsso.session.service.paasuke;

import ch.qos.logback.classic.Level;
import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.configuration.properties.PaasukeConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.XRoadConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.HttpTimeoutRuntimeException;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.paasuke.MandateTriplet.Mandate;
import ee.ria.govsso.session.xroad.XRoadHeaders;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static ee.ria.govsso.session.util.wiremock.ExtraWiremockMatchers.isUuid;
import static java.time.temporal.ChronoUnit.MILLIS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

@RequiredArgsConstructor(onConstructor_ = @Autowired)
class PaasukeServiceTest extends BaseTest {

    private static final String REPRESENTEE_ID = "ABC123";
    private static final String DELEGATE_ID = "Isikukood3";

    private final PaasukeService paasukeService;
    private final PaasukeConfigurationProperties paasukeConfigurationProperties;
    private final XRoadConfigurationProperties xRoadConfigurationProperties;

    @Test
    void fetchMandates_okResponse_mandateTripletReturned() {
        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo(DELEGATE_ID))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/paasuke/getRepresenteeDelegateMandates/ABC123_Isikukood3_ns_AGENCY-Q.json")));
        MandateTriplet expected = MandateTriplet.builder()
                .delegate(Person.builder()
                        .type("NATURAL_PERSON")
                        .firstName("Eesnimi3")
                        .surname("Perekonnanimi3")
                        .identifier(DELEGATE_ID)
                        .build())
                .representee(Person.builder()
                        .type("LEGAL_PERSON")
                        .legalName("Sukk ja Saabas OÜ")
                        .identifier("ABC123")
                        .build())
                .mandates(List.of(
                        new Mandate("BR_REPRIGHT:JUHL"),
                        new Mandate("AGENCY-Q:Edit.submit")
                ))
                .build();

        MandateTriplet actual = paasukeService.fetchMandates(REPRESENTEE_ID, DELEGATE_ID, "ns=AGENCY-Q");
        assertThat(actual, equalTo(expected));

        assertMessage()
                .withLoggerClass(PaasukeService.class)
                .withLevel(Level.INFO)
                .withMessage("PAASUKE request")
                .withMarkerMatching(marker -> marker.startsWith("http.request.method=GET, url.full=https://paasuke.localhost:12000/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q"))
                .isLoggedOnce();
        assertMessage()
                .withLoggerClass(PaasukeService.class)
                .withLevel(Level.INFO)
                .withMessage("PAASUKE response")
                .withMarkerMatching(marker -> marker.startsWith("http.response.status_code=200, http.response.body.content={"))
                .isLoggedOnce();
    }

    @Test
    void fetchMandates_4xxResponse_exceptionThrown() {
        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo(DELEGATE_ID))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        SsoException exception = assertThrows(
                SsoException.class,
                () -> paasukeService.fetchMandates(REPRESENTEE_ID, DELEGATE_ID, "ns=AGENCY-Q"));

        assertThat(exception.getErrorCode(), equalTo(ErrorCode.TECHNICAL_PAASUKE_UNAVAILABLE));
        assertMessage()
                .withLoggerClass(PaasukeService.class)
                .withLevel(Level.INFO)
                .withMessage("PAASUKE request")
                .withMarkerMatching(marker -> marker.startsWith("http.request.method=GET, url.full=https://paasuke.localhost:12000/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q"))
                .isLoggedOnce();
        assertMessage()
                .withLoggerClass(PaasukeService.class)
                .withLevel(Level.INFO)
                .withMessage("PAASUKE response")
                .withMarkerMatching(marker -> marker.startsWith("http.response.status_code=400"))
                .isLoggedOnce();
    }

    @Test
    void fetchMandates_5xxResponse_exceptionThrown() {
        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo(DELEGATE_ID))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        SsoException exception = assertThrows(
                SsoException.class,
                () -> paasukeService.fetchMandates(REPRESENTEE_ID, DELEGATE_ID, "ns=AGENCY-Q"));

        assertThat(exception.getErrorCode(), equalTo(ErrorCode.TECHNICAL_PAASUKE_UNAVAILABLE));
        assertMessage()
                .withLoggerClass(PaasukeService.class)
                .withLevel(Level.INFO)
                .withMessage("PAASUKE request")
                .withMarkerMatching(marker -> marker.startsWith("http.request.method=GET, url.full=https://paasuke.localhost:12000/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q"))
                .isLoggedOnce();
        assertMessage()
                .withLoggerClass(PaasukeService.class)
                .withLevel(Level.INFO)
                .withMessage("PAASUKE response")
                .withMarkerMatching(marker -> marker.startsWith("http.response.status_code=500"))
                .isLoggedOnce();
    }

    @Test
    void fetchMandates_requestTimesOut_exceptionThrown() {
        PAASUKE_MOCK_SERVER.stubFor(get("/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q")
                .withHeader(XRoadHeaders.CLIENT, WireMock.equalTo(xRoadConfigurationProperties.clientId()))
                .withHeader(XRoadHeaders.USER_ID, WireMock.equalTo(DELEGATE_ID))
                .withHeader(XRoadHeaders.MESSAGE_ID, isUuid())
                .willReturn(aResponse()
                        .withFixedDelay((int) paasukeConfigurationProperties.requestTimeout().plus(100, MILLIS).toMillis())
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/paasuke/getRepresenteeDelegateMandates/ABC123_Isikukood3_ns_AGENCY-Q.json")));

        SsoException exception = assertThrows(
                SsoException.class,
                () -> paasukeService.fetchMandates(REPRESENTEE_ID, DELEGATE_ID, "ns=AGENCY-Q"));

        assertThat(exception.getErrorCode(), equalTo(ErrorCode.TECHNICAL_PAASUKE_UNAVAILABLE));
        assertThat(exception.getCause(), instanceOf(HttpTimeoutRuntimeException.class));
        assertMessage()
                .withLoggerClass(PaasukeService.class)
                .withLevel(Level.INFO)
                .withMessage("PAASUKE request")
                .withMarkerMatching(marker -> marker.startsWith("http.request.method=GET, url.full=https://paasuke.localhost:12000/volitused/oraakel/representees/ABC123/delegates/Isikukood3/mandates?ns=AGENCY-Q"))
                .isLoggedOnce();
    }

}