package ee.ria.govsso.session.session;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SsoCookieTest {

    @Test
    void builder_WhenLoginChallengeNotSet_NullPointerException() {

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> SsoCookie.builder()
                        .build());

        assertThat(ex.getMessage(), equalTo("Session login request info challenge must not be blank"));
    }

    @Test
    void builder_WhenLoginChallengeIsNull_NullPointerException() {

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> SsoCookie.builder()
                        .loginChallenge(null)
                        .build());

        assertThat(ex.getMessage(), equalTo("Session login request info challenge must not be blank"));
    }

    @Test
    void builder_WhenLoginChallengeIsBlank_NullPointerException() {

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> SsoCookie.builder()
                        .loginChallenge(" ")
                        .build());

        assertThat(ex.getMessage(), equalTo("Session login request info challenge must not be blank"));
    }
}
