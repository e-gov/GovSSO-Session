package ee.ria.govsso.session.service.useragent;

import org.springframework.stereotype.Service;
import ua_parser.Client;
import ua_parser.Parser;
import ua_parser.OS;
import ua_parser.UserAgent;

@Service
public class UserAgentParserService {

    private final Parser parser = new Parser();

    public ParsedUserAgent parse(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return new ParsedUserAgent(null, null);
        }

        Client client = parser.parse(userAgent);

        String os = normalizeOs(client.os);
        String browser = normalizeUserAgent(client.userAgent);

        return new ParsedUserAgent(os, browser);
    }

    private String normalizeOs(ua_parser.OS os) {
        if (os == null || OS.OTHER.equals(os)) {
            return null;
        }
        return os.family;
    }

    private String normalizeUserAgent(ua_parser.UserAgent userAgent) {
        if (userAgent == null || UserAgent.OTHER.equals(userAgent)) {
            return null;
        }
        return userAgent.family;
    }
}
