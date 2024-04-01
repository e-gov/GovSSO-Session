package ee.ria.govsso.session.service.paasuke;

import ee.ria.govsso.session.service.hydra.Mandate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class PaasukeService {

    //TODO needs actual implementation in https://jira.ria.ee/browse/AUT-1690
    public PaasukeInfo fetchPaasukeInfo(String userId) {
        PaasukeInfo paasukeInfo = new PaasukeInfo();
        Person person = new Person();
        Mandate mandate = new Mandate();
        List<Mandate> mandates = new ArrayList<>();
        mandate.setRole("role");
        mandates.add(mandate);
        person.setFirstName("First Name");
        person.setSurname("Surname");
        person.setLegalName("Legal Name");
        person.setType("NATURAL_PERSON");
        paasukeInfo.setRepresentee(person);
        paasukeInfo.setMandates(mandates);
        return paasukeInfo;
    }

}
