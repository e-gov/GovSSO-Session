package ee.ria.govsso.session.service.ipcountry;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;

@Service
@ConditionalOnProperty(
        name = "govsso.ip-country.provider",
        havingValue = "CLOUDFLARE"
)
public class CloudflareIpCountryService implements IpCountryService {

    // https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-ipcountry
    protected static final String CF_IP_COUNTRY_HEADER = "CF-IPCountry";
    private static final Set<String> UNSUPPORTED_COUNTRY_CODES = Set.of("XX", "T1");

    @Override
    public Optional<String> resolveIpCountry(HttpServletRequest request) {
        String countryCode = request.getHeader(CF_IP_COUNTRY_HEADER);

        if (countryCode == null || countryCode.isBlank()
                || UNSUPPORTED_COUNTRY_CODES.contains(countryCode)) {
            return Optional.empty();
        }

        return Optional.of(countryCode);
    }
}
