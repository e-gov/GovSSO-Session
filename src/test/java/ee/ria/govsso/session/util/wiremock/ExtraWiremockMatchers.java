package ee.ria.govsso.session.util.wiremock;

import com.github.tomakehurst.wiremock.matching.RegexPattern;
import com.github.tomakehurst.wiremock.matching.StringValuePattern;
import lombok.experimental.UtilityClass;

@UtilityClass
public class ExtraWiremockMatchers {

    public static StringValuePattern isUuid() {
        return new RegexPattern("[0-9a-fA-F]{8}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{12}");
    }

}
