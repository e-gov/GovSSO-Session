package ee.ria.govsso.session.service.hydra;

import lombok.RequiredArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
public enum Prompt {
    CONSENT("consent");

    private static final Map<String, Prompt> promptNameMap;

    static {
        promptNameMap = new HashMap<>();

        for (Prompt prompt : Prompt.values()) {
            promptNameMap.put(prompt.promptName, prompt);
        }
    }

    private final String promptName;

    public static Prompt findByName(String promptName) {
        return promptNameMap.get(promptName);
    }
}
