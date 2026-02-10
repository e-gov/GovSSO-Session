package ee.ria.govsso.session.service.ipcountry;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.util.Optional;

import static ee.ria.govsso.session.service.ipcountry.CloudflareIpCountryService.CF_IP_COUNTRY_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

class CloudflareIpCountryServiceTest {

    private CloudflareIpCountryService service;
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        service = new CloudflareIpCountryService();
        request = Mockito.mock(HttpServletRequest.class);
    }

    @Test
    void whenValidCountryCode_thenReturnsCountry() {
        when(request.getHeader(CF_IP_COUNTRY_HEADER)).thenReturn("EE");

        Optional<String> result = service.resolveIpCountry(request);

        assertThat(result).contains("EE");
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   ", "XX", "T1"})
    void whenCountryHeaderIsInvalid_thenReturnsEmpty(String headerValue) {
        when(request.getHeader(CF_IP_COUNTRY_HEADER)).thenReturn(headerValue);

        Optional<String> result = service.resolveIpCountry(request);

        assertThat(result).isEmpty();
    }
}
