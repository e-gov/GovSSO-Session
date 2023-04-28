package ee.ria.govsso.session.service.admin;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;

import java.time.OffsetDateTime;
import java.util.Map;

@Builder
@Jacksonized
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record ServiceSession(@NonNull Map<String, String> clientNames,
                             @NonNull OffsetDateTime authenticatedAt,
                             @NonNull OffsetDateTime expiresAt,
                             @NonNull OffsetDateTime lastUpdatedAt) {
}
