package ee.ria.govsso.session.service.ipcountry;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;

class NoOpIpCountryServiceTest {

    @Test
    void resolveIpCountry_alwaysReturnsEmpty() {
        NoOpIpCountryService service = new NoOpIpCountryService();
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        assertThat(service.resolveIpCountry(request)).isEmpty();
    }
}
