package ee.ria.govsso.session.service.hydra;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Getter
@RequiredArgsConstructor
public enum LevelOfAssurance {

    LOW("low", 1),
    SUBSTANTIAL("substantial", 2),
    HIGH("high", 3);

    public static final LevelOfAssurance DEFAULT = HIGH;
    private static final Map<String, LevelOfAssurance> acrNameMap;

    static {
        acrNameMap = new HashMap<>();

        for (LevelOfAssurance loa : LevelOfAssurance.values()) {
            acrNameMap.put(loa.acrName, loa);
        }
    }

    private final String acrName;
    private final int acrLevel;

    public static LevelOfAssurance findByAcrName(String acrName) {
        return acrNameMap.get(acrName);
    }
}
