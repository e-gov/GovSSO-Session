package ee.ria.govsso.session.util;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

class CookieUtilTest {

    @Test
    void containsSessionId_WhenValidFormatAndContainsSessionId_ReturnsTrue() {
        String cookieValue = "MTY3Mzk1MTE0NXxEdi1CQkFFQ180SUFBUkFCRUFBQVlmLUNBQUlHYzNSeWFXNW5EQWtBQjIxaGVGOWhaMlVGYVc1ME5qUUVCZ0Q4eDR6MldnWnpkSEpwYm1jTUJRQURjMmxrQm5OMGNtbHVad3dtQUNRMll6Y3hORGxoWXkwNE0yUTFMVFF4T1RBdFlUYzBOUzA0TnpRMk5USXhNRGN6TTJNPXzfiGiUYGPxKzpveyuRYrmxCI_cTGz4kMXeVigL_Ab7bQ==";
        boolean sessionId = CookieUtil.containsSessionId(cookieValue, "6c7149ac-83d5-4190-a745-87465210733c");

        assertThat(sessionId, is(true));
    }

    @Test
    void containsSessionId_WhenInvalidHashAndContainsSessionId_ReturnsTrue() {
        String cookieValue = "MTY3Mzk1MTE0NXxEdi1CQkFFQ180SUFBUkFCRUFBQVlmLUNBQUlHYzNSeWFXNW5EQWtBQjIxaGVGOWhaMlVGYVc1ME5qUUVCZ0Q4eDR6MldnWnpkSEpwYm1jTUJRQURjMmxrQm5OMGNtbHVad3dtQUNRMll6Y3hORGxoWXkwNE0yUTFMVFF4T1RBdFlUYzBOUzA0TnpRMk5USXhNRGN6TTJNPXxpbnZhbGlkaGFzaA==";
        boolean sessionId = CookieUtil.containsSessionId(cookieValue, "6c7149ac-83d5-4190-a745-87465210733c");

        assertThat(sessionId, is(true));
    }

    @Test
    void containsSessionId_WhenInvalidMaxValidTimeAndContainsSessionId_ReturnsTrue() {
        String cookieValue = "MDAwMDAwMDAwMHxEdi1CQkFFQ180SUFBUkFCRUFBQVlmLUNBQUlHYzNSeWFXNW5EQWtBQjIxaGVGOWhaMlVGYVc1ME5qUUVCZ0Q4eDR6MldnWnpkSEpwYm1jTUJRQURjMmxrQm5OMGNtbHVad3dtQUNRMll6Y3hORGxoWXkwNE0yUTFMVFF4T1RBdFlUYzBOUzA0TnpRMk5USXhNRGN6TTJNPXzfiGhgYys6b3srYghMbFYoCwZt";
        boolean sessionId = CookieUtil.containsSessionId(cookieValue, "6c7149ac-83d5-4190-a745-87465210733c");

        assertThat(sessionId, is(true));
    }

    @Test
    void containsSessionId_WhenMissingSeparator_ReturnsFalse() {
        String cookieValue = "MTY3Mzk1MTE0NXxEdi1CQkFFQ180SUFBUkFCRUFBQVlmLUNBQUlHYzNSeWFXNW5EQWtBQjIxaGVGOWhaMlVGYVc1ME5qUUVCZ0Q4eDR6MldnWnpkSEpwYm1jTUJRQURjMmxrQm5OMGNtbHVad3dtQUNRMll6Y3hORGxoWXkwNE0yUTFMVFF4T1RBdFlUYzBOUzA0TnpRMk5USXhNRGN6TTJNPQ==";
        boolean sessionId = CookieUtil.containsSessionId(cookieValue, "6c7149ac-83d5-4190-a745-87465210733c");

        assertThat(sessionId, is(false));
    }

    @Test
    void containsSessionId_WhenThirdPartContainsSeparator_ReturnsTrue() {
        String cookieValue = "MTY4MDE2MDc3MnxEdi1CQkFFQ180SUFBUkFCRUFBQVFmLUNBQUVHYzNSeWFXNW5EQVVBQTNOcFpBWnpkSEpwYm1jTUpnQWtPRFZrTWpZMlpXVXRNR1kzTlMwME1EazJMVGcwWVRVdE4yVTJaakF4WmpreU1UUXp8Tzvv7c2_G7HpaX78QC3cunzpaeVnAg_dcNvNQJ_4PfE=";
        boolean sessionId = CookieUtil.containsSessionId(cookieValue, "85d266ee-0f75-4096-84a5-7e6f01f92143");

        assertThat(sessionId, is(true));
    }

    @Test
    void containsSessionId_WhenRandomData_ReturnsFalse() {
        String cookieValue = "abcdefgh12345678!#¤%&/()?=";
        boolean sessionId = CookieUtil.containsSessionId(cookieValue, "6c7149ac-83d5-4190-a745-87465210733c");

        assertThat(sessionId, is(false));
    }

    @Test
    void containsSessionId_WhenEmptyString_ReturnsFalse() {
        boolean sessionId = CookieUtil.containsSessionId("", "6c7149ac-83d5-4190-a745-87465210733c");

        assertThat(sessionId, is(false));
    }

    @Test
    void containsSessionId_WhenNull_ReturnsFalse() {
        boolean sessionId = CookieUtil.containsSessionId(null, "6c7149ac-83d5-4190-a745-87465210733c");

        assertThat(sessionId, is(false));
    }
}