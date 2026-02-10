package ee.ria.govsso.session.service.useragent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.util.unit.DataSize;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class UserAgentParserServiceTest {

    private final UserAgentParserService service = new UserAgentParserService();

    @Test
    void parseDeviceInfo_whenUserAgentIsNull_returnsUnknown() {
        assertResult(service.parse(null), null, null);
    }

    @Test
    void parseDeviceInfo_whenUserAgentIsBlank_returnsUnknown() {
        assertResult(service.parse("   "), null, null);
    }

    @ParameterizedTest
    @MethodSource("commonUserAgentCases")
    void parseDeviceInfo_commonCases(
            String userAgent,
            String expectedOs,
            String expectedBrowser
    ) {
        assertResult(service.parse(userAgent), expectedOs, expectedBrowser);
    }

    static Stream<Arguments> commonUserAgentCases() {
        return Stream.of(
                Arguments.of(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
                                "AppleWebKit/537.36 (KHTML, like Gecko) " +
                                "Chrome/120.0.0.0 Safari/537.36",
                        "Windows",
                        "Chrome"
                ),
                Arguments.of(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) " +
                                "Gecko/20100101 Firefox/121.0",
                        "Windows",
                        "Firefox"
                ),
                Arguments.of(
                        "Mozilla/5.0 (Linux; Android 13; Pixel 7) " +
                                "AppleWebKit/537.36 (KHTML, like Gecko) " +
                                "Chrome/120.0.0.0 Mobile Safari/537.36",
                        "Android",
                        "Chrome Mobile"
                ),
                Arguments.of(
                        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) " +
                                "AppleWebKit/605.1.15 (KHTML, like Gecko) " +
                                "Version/17.2 Mobile/15E148 Safari/604.1",
                        "iOS",
                        "Mobile Safari"
                ),
                Arguments.of(
                        "unknown",
                        null,
                        null
                ),
                Arguments.of(
                        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                        null,
                        "Googlebot"
                ),
                Arguments.of(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        "Windows",
                        null
                )
        );
    }

    @Test
    void parseDeviceInfo_whenUserAgentIsVeryLong_doesNotFail() {
        // Default max HTTP request header size in Spring Boot (8 KB)
        // https://docs.spring.io/spring-boot/3.5/appendix/application-properties/index.html#application-properties.server.server.max-http-request-header-size
        int maxHeaderSize = (int) DataSize.ofKilobytes(8).toBytes();

        String longUserAgent = "a".repeat(maxHeaderSize);

        ParsedUserAgent result = service.parse(longUserAgent);

        assertThat(result.os(), equalTo(null));
        assertThat(result.browser(), equalTo(null));
    }

    private void assertResult(ParsedUserAgent result, String expectedOs, String expectedBrowser) {
        assertThat(result.os(), equalTo(expectedOs));
        assertThat(result.browser(), equalTo(expectedBrowser));
    }

}
