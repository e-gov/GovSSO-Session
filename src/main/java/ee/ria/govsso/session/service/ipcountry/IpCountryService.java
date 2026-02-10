package ee.ria.govsso.session.service.ipcountry;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

public interface IpCountryService {
    Optional<String> resolveIpCountry(HttpServletRequest request);
}