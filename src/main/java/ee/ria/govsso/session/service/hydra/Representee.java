package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.util.List;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Representee {

    private RepresenteeRequestStatus status;
    private String type;
    private String sub;
    private String givenName;
    private String familyName;
    private String name;
    private List<Mandate> mandates;

    @Builder
    public record Mandate(
            @NonNull String role
    ) {}
}
