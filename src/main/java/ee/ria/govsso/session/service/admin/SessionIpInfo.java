package ee.ria.govsso.session.service.admin;

import lombok.Builder;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

@Builder
@Jacksonized
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record SessionIpInfo(
        @NonNull String ipAddress,
        String country
) {
}
