package ee.ria.govsso.session.service.useragent;

import java.io.IOException;
import java.io.InputStream;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import ua_parser.Client;
import ua_parser.OS;
import ua_parser.Parser;
import ua_parser.UserAgent;

@Service
public class UserAgentParserService {

    private static final String REGEXES_RESOURCE_PATH = "useragent/regexes.yaml";

    private final Parser parser = createParser();

    public ParsedUserAgent parse(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return new ParsedUserAgent(null, null);
        }

        Client client = parser.parse(userAgent);

        String os = normalizeOs(client.os);
        String browser = normalizeUserAgent(client.userAgent);

        return new ParsedUserAgent(os, browser);
    }

    private Parser createParser() {
        ClassPathResource resource = new ClassPathResource(REGEXES_RESOURCE_PATH);

        try (InputStream inputStream = resource.getInputStream()) {
            return new Parser(inputStream);
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Failed to load user agent regexes from classpath resource: " + REGEXES_RESOURCE_PATH, e
            );
        }
    }

    private String normalizeOs(OS os) {
        if (os == null || OS.OTHER.equals(os)) {
            return null;
        }
        return os.family;
    }

    private String normalizeUserAgent(UserAgent userAgent) {
        if (userAgent == null || UserAgent.OTHER.equals(userAgent)) {
            return null;
        }
        return userAgent.family;
    }
}
