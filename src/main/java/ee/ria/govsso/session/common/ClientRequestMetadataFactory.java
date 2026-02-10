package ee.ria.govsso.session.common;

import ee.ria.govsso.session.service.ipcountry.IpCountryService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ClientRequestMetadataFactory {

    private final IpCountryService ipCountryService;

    public ClientRequestMetadata fromRequest(HttpServletRequest request) {
        return ClientRequestMetadata.builder()
                .ipAddress(request.getRemoteAddr())
                .userAgent(request.getHeader(HttpHeaders.USER_AGENT))
                .ipCountry(ipCountryService.resolveIpCountry(request).orElse(null))
                .build();
    }
}
