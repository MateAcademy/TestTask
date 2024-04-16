package ua.itcenter.db;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.experimental.FieldDefaults;
import ua.itcenter.model.VulnerabilityScript;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Getter
@FieldDefaults(level = AccessLevel.PRIVATE)
public class Storage {

    final List<VulnerabilityScript> scriptList = new ArrayList<>() {{
        add(new VulnerabilityScript(1, Arrays.asList(2, 3, 3)));
        add(new VulnerabilityScript(4, new ArrayList<>()));
        add(new VulnerabilityScript(2, Arrays.asList(6)));
        add(new VulnerabilityScript(3, Arrays.asList(6)));
        add(new VulnerabilityScript(6, Arrays.asList(4)));
    }};

}
