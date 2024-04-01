package ee.ria.govsso.session.service.paasuke;

import ee.ria.govsso.session.service.hydra.Mandate;
import lombok.Data;

import java.util.List;

@Data
public class PaasukeInfo {

    private Person representee;
    List<Mandate> mandates;
}
