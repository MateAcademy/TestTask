package ua.itcenter.service;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.experimental.FieldDefaults;
import ua.itcenter.db.Storage;
import ua.itcenter.model.VulnerabilityScript;
import ua.itcenter.model.KeyValueMap;

import java.util.*;

@Getter
@FieldDefaults(level = AccessLevel.PRIVATE)
public class ScriptExecutionPlan {

    final Storage storage;
    final Set<Integer> executionPlan = new LinkedHashSet<>();
    final List<VulnerabilityScript> errorScripts = new ArrayList<>();
    final List<KeyValueMap> errorKeyValueMap = new ArrayList<>();

    public ScriptExecutionPlan(Storage storage) {
        this.storage = storage;
    }

    public Set<Integer> start() {
        try {
            List<VulnerabilityScript> scripts = storage.getScriptList();
            findErrorsAndDeleteThemFromScripts(scripts);
            receiveExecutionPlan(scripts);
            System.out.println(STR."Execution Plan: \{executionPlan}");
            System.err.println(STR."ErrorScripts: \{errorScripts}");
        } catch (Exception e) {
            System.err.print(STR."The program ended with errors: \{e}");
        }
        return executionPlan;
    }

    private void receiveExecutionPlan(List<VulnerabilityScript> scripts) {
        List<KeyValueMap> mapList = getMapFromScriptList(scripts);
        findLastValueOfScriptAndAddInExecutionPlan(mapList);

        while (!mapList.isEmpty()) {
            addSimpleValuesToExecutionPlan(mapList);
            addDuplicateValuesToExecutionPlan(mapList);
            checkingOnErrorsAndAddingResultToErrorKeyValueMap(mapList);
        }

        if (!errorKeyValueMap.isEmpty()) {
            Iterator<KeyValueMap> iterator = errorKeyValueMap.iterator();
            while (iterator.hasNext()) {
                KeyValueMap element = iterator.next();
                int key = element.getKey();
                Map<Integer, Integer> value = element.getValue();

                for (Map.Entry<Integer, Integer> entries : value.entrySet()) {
                    Integer keyFromMyMap = entries.getKey();
                    Integer valueFromMyMap = entries.getValue();

                    if (valueFromMyMap == 1) {
                        VulnerabilityScript vulnerabilityScript = new VulnerabilityScript();

                        Integer scriptId = key;
                        List<Integer> dependencies = new ArrayList<>() {{
                            add(keyFromMyMap);
                        }};
                        vulnerabilityScript.setScriptId(scriptId);
                        vulnerabilityScript.setDependencies(dependencies);

                        errorScripts.add(vulnerabilityScript);
                        iterator.remove();
                    }
                }
            }
        }
    }

    private List<KeyValueMap> getMapFromScriptList(List<VulnerabilityScript> scripts) {
        List<KeyValueMap> mapMapList = new ArrayList<>();

        for (VulnerabilityScript vs : scripts) {
            Integer scriptId = vs.getScriptId();

            if (scriptId == null) {
                errorScripts.add(vs);
                System.err.println(STR."ERROR: \{vs}");
                continue;
            }

            List<Integer> dependencies = vs.getDependencies();
            if (dependencies == null) {
                dependencies = new ArrayList<>();
            }

            int index = 0;
            for (Integer dependency : dependencies) {
                index = 0;
                if (dependency == null) {
                    errorScripts.add(vs);
                    System.err.println(STR."ERROR: \{vs}");
                    index = 1;
                }
            }
            if (index == 1)
                continue;

            int numberOfDependencies = dependencies.size();

            if (numberOfDependencies == 1) {
                KeyValueMap keyValueMap = new KeyValueMap();

                Map<Integer, Integer> map = new HashMap<>();
                map.put(dependencies.get(0), 1);

                keyValueMap.setKey(scriptId);
                keyValueMap.setValue(map);
                mapMapList.add(keyValueMap);
            } else if (numberOfDependencies > 1) {
                for (Integer counter : dependencies) {
                    KeyValueMap keyValueMap = new KeyValueMap();
                    Map<Integer, Integer> map = new HashMap<>();
                    map.put(counter, numberOfDependencies);
                    keyValueMap.setKey(scriptId);
                    keyValueMap.setValue(map);

                    mapMapList.add(keyValueMap);
                }
            } else {
                KeyValueMap mapMap = new KeyValueMap();

                Map<Integer, Integer> map = new HashMap<>();
                map.put(0, 1);

                mapMap.setKey(scriptId);
                mapMap.setValue(map);

                mapMapList.add(mapMap);
            }
        }
        return mapMapList;
    }

    private void findLastValueOfScriptAndAddInExecutionPlan(List<KeyValueMap> keyValueMaps) {
        if (keyValueMaps != null && !keyValueMaps.isEmpty()) {
            Iterator<KeyValueMap> iterator = keyValueMaps.iterator();

            while (iterator.hasNext()) {
                KeyValueMap element = iterator.next();
                if (element.getValue().containsKey(0)) {
                    int valueForExecutionPlan = element.getKey();
                    executionPlan.add(valueForExecutionPlan);
                    iterator.remove();
                }
            }
        }
    }

    private void addSimpleValuesToExecutionPlan(List<KeyValueMap> keyValueMaps) {
        if (keyValueMaps != null && !keyValueMaps.isEmpty()) {
            Iterator<KeyValueMap> iterator = keyValueMaps.iterator();

            while (iterator.hasNext()) {
                KeyValueMap element = iterator.next();
                int key = element.getKey();
                Map<Integer, Integer> value = element.getValue();

                for (Map.Entry<Integer, Integer> entries : value.entrySet()) {
                    Integer keyFromMyMap = entries.getKey();
                    Integer valueFromMyMap = entries.getValue();

                    if (valueFromMyMap == 1 && executionPlan.contains(keyFromMyMap)) {
                        executionPlan.add(key);
                        iterator.remove();
                    }
                }
            }
        }
    }

    private void addDuplicateValuesToExecutionPlan(List<KeyValueMap> keyValueMaps) {
        if (keyValueMaps != null && !keyValueMaps.isEmpty()) {
            List<Integer> listToDelete = new ArrayList<>();

            keyValueMaps.sort(Comparator.comparingInt(KeyValueMap::getKey));
            Iterator<KeyValueMap> iterator = keyValueMaps.iterator();

            Integer keyDuplicat = null;
            int count = 0;
            boolean delite = false;

            while (iterator.hasNext()) {
                KeyValueMap element = iterator.next();
                int key = element.getKey();

                if (!Objects.equals(key, keyDuplicat)) {
                    keyDuplicat = key;
                    count = 1;
                    delite = false;
                } else if (keyDuplicat == key) {
                    count++;
                }

                Map<Integer, Integer> value = element.getValue();

                for (Map.Entry<Integer, Integer> entries : value.entrySet()) {
                    int keyFromMyMap = entries.getKey();
                    int valueFromMyMap = entries.getValue();

                    if (count == 1 && executionPlan.contains(keyFromMyMap)) {
                        delite = true;
                    } else if (count > 1 && executionPlan.contains(keyFromMyMap) && delite) {
                        delite = true;
                    } else {
                        delite = false;
                    }

                    if (valueFromMyMap == count && delite) {
                        executionPlan.add(key);
                        listToDelete.add(element.getKey());
                    }
                }
            }

            if (!listToDelete.isEmpty()) {
                Iterator<KeyValueMap> iterator2 = keyValueMaps.iterator();
                while (iterator2.hasNext()) {
                    KeyValueMap element2 = iterator2.next();
                    Integer key1 = element2.getKey();
                    if (listToDelete.contains(key1)) {
                        iterator2.remove();
                    }
                }
            }
        }
    }

    private void checkingOnErrorsAndAddingResultToErrorKeyValueMap(List<KeyValueMap> keyValueMaps) {
        if (keyValueMaps != null && !keyValueMaps.isEmpty()) {
            Iterator<KeyValueMap> iterator = keyValueMaps.iterator();

            while (iterator.hasNext()) {
                KeyValueMap element = iterator.next();  // 2 - 3 - 2
                int key = element.getKey();
                Map<Integer, Integer> value = element.getValue();

                for (Map.Entry<Integer, Integer> entries : value.entrySet()) {
                    Integer keyFromMyMap = entries.getKey();
                    Integer valueFromMyMap = entries.getValue();

                    if (valueFromMyMap == 1 && executionPlan.contains(keyFromMyMap)) {
                        executionPlan.add(key);
                        iterator.remove();
                    } else if (valueFromMyMap == 1 && !executionPlan.contains(keyFromMyMap)) {
                        boolean variable = false;
                        Iterator<KeyValueMap> iterator2 = keyValueMaps.iterator();
                        while (iterator2.hasNext()) {
                            KeyValueMap element2 = iterator2.next();
                            int key2 = element2.getKey();
                            if (keyFromMyMap == key2) {
                                variable = true;
                            }
                        }

                        if (!variable) {
                            errorKeyValueMap.add(element);
                            iterator.remove();
                        }
                    }
                }
            }
        }
    }

    private void findErrorsAndDeleteThemFromScripts(List<VulnerabilityScript> scripts) {
        boolean count;
        Iterator<VulnerabilityScript> iterator = scripts.iterator();

        while (iterator.hasNext()) {
            count = false;
            VulnerabilityScript vs = iterator.next();

            Integer scriptsId = vs.getScriptId();

            if (scriptsId == null) {
                errorScripts.add(vs);
                iterator.remove();
                continue;
            }

            List<Integer> dependencies = vs.getDependencies();
            if (dependencies!=null) {
                for (Integer dependency : dependencies) {
                    Integer dep = dependency;

                    if (dep == null || Objects.equals(scriptsId, dep)) {
                        errorScripts.add(vs);
                        iterator.remove();
                        break;
                    }

                    for (VulnerabilityScript vsc : scripts) {
                        Integer scriptId = vsc.getScriptId();
                        if (dep.equals(scriptId)) {
                            count = true;
                            break;
                        }
                    }

                    if (!count) {
                        errorScripts.add(vs);
                        iterator.remove();
                        break;
                    }
                }
            }
        }
    }

}
