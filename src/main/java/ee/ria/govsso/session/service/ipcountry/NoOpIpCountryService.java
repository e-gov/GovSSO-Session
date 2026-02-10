package ee.ria.govsso.session.service.ipcountry;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@ConditionalOnProperty(
        name = "govsso.ip-country.provider",
        havingValue = "NONE",
        matchIfMissing = true
)
public class NoOpIpCountryService implements IpCountryService {

    @Override
    public Optional<String> resolveIpCountry(HttpServletRequest request) {
        return Optional.empty();
    }
}
