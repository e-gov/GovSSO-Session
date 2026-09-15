package ee.ria.govsso.session.token;

import com.fasterxml.jackson.annotation.JsonInclude;
import ee.ria.govsso.session.configuration.jackson.InstantAsEpochSeconds;
import lombok.Builder;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonNaming;
import tools.jackson.databind.annotation.JsonSerialize;

import java.time.Instant;

@Builder
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record UserAttributes(
        String subject,
        @JsonSerialize(using = InstantAsEpochSeconds.Serializer.class)
        @JsonDeserialize(using = InstantAsEpochSeconds.Deserializer.class)
        Instant tokenIssuedAt,
        @JsonSerialize(using = InstantAsEpochSeconds.Serializer.class)
        @JsonDeserialize(using = InstantAsEpochSeconds.Deserializer.class)
        Instant sessionStartTime,
        String acr,
        String[] amr,
        String givenName,
        String familyName,
        String birthdate,
        String phoneNumber,
        Boolean phoneNumberVerified) {
}
