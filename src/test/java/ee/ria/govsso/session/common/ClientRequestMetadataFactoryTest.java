package ee.ria.govsso.session.common;

import ee.ria.govsso.session.service.ipcountry.IpCountryService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;

import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.when;

class ClientRequestMetadataFactoryTest {

    private IpCountryService ipCountryService;
    private ClientRequestMetadataFactory factory;
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        ipCountryService = Mockito.mock(IpCountryService.class);
        factory = new ClientRequestMetadataFactory(ipCountryService);
        request = Mockito.mock(HttpServletRequest.class);
    }

    @Test
    void whenRequestContainsMetadataAndCountryResolved_thenBuildsMetadata() {
        when(request.getRemoteAddr()).thenReturn("192.168.1.1");
        when(request.getHeader(HttpHeaders.USER_AGENT)).thenReturn("Mozilla/5.0");
        when(ipCountryService.resolveIpCountry(request)).thenReturn(Optional.of("EE"));

        ClientRequestMetadata result = factory.fromRequest(request);

        assertThat(result.ipAddress()).isEqualTo("192.168.1.1");
        assertThat(result.userAgent()).isEqualTo("Mozilla/5.0");
        assertThat(result.ipCountry()).isEqualTo("EE");
    }

    @Test
    void whenCountryIsNotResolved_thenSetsCountryToNull() {
        when(request.getRemoteAddr()).thenReturn("192.168.1.1");
        when(request.getHeader(HttpHeaders.USER_AGENT)).thenReturn("Mozilla/5.0");
        when(ipCountryService.resolveIpCountry(request)).thenReturn(Optional.empty());

        ClientRequestMetadata result = factory.fromRequest(request);

        assertThat(result.ipAddress()).isEqualTo("192.168.1.1");
        assertThat(result.userAgent()).isEqualTo("Mozilla/5.0");
        assertThat(result.ipCountry()).isNull();
    }
}
