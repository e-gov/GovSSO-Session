package ee.ria.govsso.session.service.hydra;

import ee.ria.govsso.session.configuration.jackson.InstantAsEpochSeconds;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonNaming;
import tools.jackson.databind.annotation.JsonSerialize;

import java.time.Instant;
import java.util.List;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LoginSessionInfo {

    @NotBlank
    private String acr;
    @NotEmpty
    private List<String> amr;
    @NotNull
    @JsonSerialize(using = InstantAsEpochSeconds.Serializer.class)
    @JsonDeserialize(using = InstantAsEpochSeconds.Deserializer.class)
    private Instant authTime;
    @NotBlank
    private String birthdate;
    @NotBlank
    private String familyName;
    @NotBlank
    private String givenName;
    private String phoneNumber;
    private Boolean phoneNumberVerified;
    @NotBlank
    private String subject;
}
