package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.util.List;

@Builder
@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RepresenteeList {
    private RepresenteeListRequestStatus status;
    private List<Representee> list;

    public enum RepresenteeListRequestStatus {
        REPRESENTEE_LIST_CURRENT,
        SERVICE_NOT_AVAILABLE
    }
}
