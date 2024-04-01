package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

import java.util.List;
@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Representee {

    private String type;
    private String sub;
    private String givenName;
    private String familyName;
    private List<Mandate> mandates;
}
