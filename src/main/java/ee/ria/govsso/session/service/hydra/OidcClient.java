package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;
import net.logstash.logback.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class OidcClient {
    private Institution institution;
    private Map<String, String> nameTranslations = new HashMap<>();
    private Map<String, String> shortNameTranslations = new HashMap<>();
    private String logo;

    @JsonGetter("logo")
    public String getLogoSummary() {
        if (StringUtils.isBlank(logo)) {
            return logo;
        }
        return String.format("[%d] chars", logo.length());
    }
}
