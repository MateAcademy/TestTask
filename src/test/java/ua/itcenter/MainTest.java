package ua.itcenter;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import ua.itcenter.db.Storage;
import ua.itcenter.model.KeyValueMap;
import ua.itcenter.model.VulnerabilityScript;
import ua.itcenter.service.ScriptExecutionPlan;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MainTest {
    @Mock
    private Storage storageMock;
    @InjectMocks
    private ScriptExecutionPlan scriptExecutionPlan;
    private static List<VulnerabilityScript> scripts;

    @BeforeAll
    static void preparedData() {
        scripts = new ArrayList<>() {{
            add(new VulnerabilityScript(1, Arrays.asList(2)));
            add(new VulnerabilityScript(4, new ArrayList<>()));
            add(new VulnerabilityScript(2, Arrays.asList(4)));
        }};
    }

    @Test
    void start_shouldGetExecutionPlan_whenScriptsEqualsNull() {
        List<VulnerabilityScript> scripts = new ArrayList<>() {{
            add(new VulnerabilityScript(null, List.of(2)));
            add(new VulnerabilityScript(2, new ArrayList<>()));
        }};

        when(storageMock.getScriptList()).thenReturn(scripts);

        HashSet<Integer> expectedSet = new LinkedHashSet<>();
        expectedSet.add(2);

        List<VulnerabilityScript> expectedErrorScripts = new ArrayList<>() {{
            add(new VulnerabilityScript(null, List.of(2)));
        }};

        Set<Integer> actual = scriptExecutionPlan.start();
        List<VulnerabilityScript> errorScriptsFromProgram = scriptExecutionPlan.getErrorScripts();

        assertNotNull(actual);
        assertEquals(1, actual.size());
        assertEquals(expectedSet, actual);
        assertEquals(expectedErrorScripts, errorScriptsFromProgram);
    }

    @Test
    void start_shouldGetExecutionPlan_whenDependenciesInScriptsEqualsNull() {
        List<VulnerabilityScript> scripts = new ArrayList<>() {{
            add(new VulnerabilityScript(1, List.of(2)));
            add(new VulnerabilityScript(2, null));
        }};

        when(storageMock.getScriptList()).thenReturn(scripts);

        HashSet<Integer> expectedSet = new LinkedHashSet<>();
        expectedSet.add(1);
        expectedSet.add(2);

        List<VulnerabilityScript> expectedErrorScripts = new ArrayList<>();

        Set<Integer> actual = scriptExecutionPlan.start();
        List<VulnerabilityScript> errorScriptsFromProgram = scriptExecutionPlan.getErrorScripts();

        assertNotNull(actual);
        assertEquals(2, actual.size());
        assertEquals(expectedSet, actual);
        assertEquals(expectedErrorScripts, errorScriptsFromProgram);
    }

    @Test
    void start_shouldGetExecutionPlan_whenDependenciesError() {
        List<VulnerabilityScript> scripts = new ArrayList<>() {{
            add(new VulnerabilityScript(1, List.of(2)));
        }};

        when(storageMock.getScriptList()).thenReturn(scripts);

        HashSet<Integer> expectedSet = new LinkedHashSet<>();

        List<VulnerabilityScript> expectedErrorScripts = new ArrayList<>() {{
            add(new VulnerabilityScript(1, List.of(2)));
        }};

        Set<Integer> actual = scriptExecutionPlan.start();
        List<VulnerabilityScript> errorScriptsFromProgram = scriptExecutionPlan.getErrorScripts();

        assertNotNull(actual);
        assertEquals(0, actual.size());
        assertEquals(expectedSet, actual);
        assertEquals(expectedErrorScripts, errorScriptsFromProgram);
    }

    @Test
    void start_shouldGetExecutionPlan_whenScriptsEqualsNullAndDependenciesInScriptsEqualsNull() {
        List<VulnerabilityScript> scripts = new ArrayList<>() {{
            add(new VulnerabilityScript(null, List.of(2)));
            add(new VulnerabilityScript(2, null));
        }};

        when(storageMock.getScriptList()).thenReturn(scripts);

        HashSet<Integer> expectedSet = new LinkedHashSet<>();
        expectedSet.add(2);

        List<VulnerabilityScript> expectedErrorScripts = new ArrayList<>() {{
            add(new VulnerabilityScript(null, List.of(2)));
        }};

        Set<Integer> actual = scriptExecutionPlan.start();
        List<VulnerabilityScript> errorScriptsFromProgram = scriptExecutionPlan.getErrorScripts();

        assertNotNull(actual);
        assertEquals(1, actual.size());
        assertEquals(expectedSet, actual);
        assertEquals(expectedErrorScripts, errorScriptsFromProgram);
    }

    @Test
    void start_shouldGetExecutionPlan_whenTwoDependenciesInScriptsEqualsNull() {
        List<VulnerabilityScript> scripts = new ArrayList<>() {{
            add(new VulnerabilityScript(1, null));
            add(new VulnerabilityScript(2, null));
        }};

        when(storageMock.getScriptList()).thenReturn(scripts);

        HashSet<Integer> expectedSet = new LinkedHashSet<>();
        expectedSet.add(1);
        expectedSet.add(2);

        List<VulnerabilityScript> ExpectedErrorScripts = new ArrayList<>();

        Set<Integer> actual = scriptExecutionPlan.start();
        List<VulnerabilityScript> errorScriptsFromProgram = scriptExecutionPlan.getErrorScripts();

        assertNotNull(actual);
        assertEquals(2, actual.size());
        assertEquals(expectedSet, actual);
        assertEquals(ExpectedErrorScripts, errorScriptsFromProgram);
    }

    @Test
    void start_shouldGetExecutionPlan_whenOneOfTheValuesInDependenciesEqualsNull() {
        List<VulnerabilityScript> scripts = new ArrayList<>() {{
            add(new VulnerabilityScript(1, Arrays.asList(2, null)));
            add(new VulnerabilityScript(2, null));
        }};

        when(storageMock.getScriptList()).thenReturn(scripts);

        HashSet<Integer> expectedSet = new LinkedHashSet<>();
        expectedSet.add(2);

        List<VulnerabilityScript> ExpectedErrorScripts = new ArrayList<>() {{
            add(new VulnerabilityScript(1, Arrays.asList(2, null)));
        }};

        Set<Integer> actual = scriptExecutionPlan.start();
        List<VulnerabilityScript> errorScriptsFromProgram = scriptExecutionPlan.getErrorScripts();

        assertNotNull(actual);
        assertEquals(1, actual.size());
        assertEquals(expectedSet, actual);
        assertEquals(ExpectedErrorScripts, errorScriptsFromProgram);
    }

    @Test
    void start_getError_whenThereIsNoSuchDependenceAndOneDependenceEqualsNull() {
        List<VulnerabilityScript> scripts = new ArrayList<>() {{
            add(new VulnerabilityScript(2, Arrays.asList(3, null)));
        }};

        when(storageMock.getScriptList()).thenReturn(scripts);

        HashSet<Integer> expectedSet = new LinkedHashSet<>();

        List<VulnerabilityScript> expectedErrorScripts = new ArrayList<>() {{
            add(new VulnerabilityScript(2, Arrays.asList(3, null)));
        }};

        Set<Integer> actual = scriptExecutionPlan.start();
        List<VulnerabilityScript> errorScriptsFromProgram = scriptExecutionPlan.getErrorScripts();

        assertNotNull(actual);
        assertEquals(0, actual.size());
        assertEquals(expectedSet, actual);
        assertEquals(expectedErrorScripts, errorScriptsFromProgram);
    }

    @Test
    void start_getError_whenDependenceEqualsNullAntThereIsNoSuchSecondDependence() {
        List<VulnerabilityScript> scripts = new ArrayList<>() {{
            add(new VulnerabilityScript(2, Arrays.asList(null, 3)));
        }};

        when(storageMock.getScriptList()).thenReturn(scripts);

        HashSet<Integer> expectedSet = new LinkedHashSet<>();

        List<VulnerabilityScript> expectedErrorScripts = new ArrayList<>() {{
            add(new VulnerabilityScript(2, Arrays.asList(null, 3)));
        }};

        Set<Integer> actual = scriptExecutionPlan.start();
        List<VulnerabilityScript> errorScriptsFromProgram = scriptExecutionPlan.getErrorScripts();

        assertNotNull(actual);
        assertEquals(0, actual.size());
        assertEquals(expectedSet, actual);
        assertEquals(expectedErrorScripts, errorScriptsFromProgram);
    }


    @Test
    void start_shouldGetExecutionPlan_whenLoopingAndOneOfDependenciesEqualsNull() {
        List<VulnerabilityScript> scripts = new ArrayList<>() {{
            // add(new VulnerabilityScript(1,  Arrays.asList(2)));
            add(new VulnerabilityScript(2, Arrays.asList(2, null)));
        }};

        when(storageMock.getScriptList()).thenReturn(scripts);

        HashSet<Integer> expectedSet = new LinkedHashSet<>();

        List<VulnerabilityScript> expectedErrorScripts = new ArrayList<>() {{
            // add(new VulnerabilityScript(1,  Arrays.asList(2)));
            add(new VulnerabilityScript(2, Arrays.asList(2, null)));
        }};

        Set<Integer> actual = scriptExecutionPlan.start();
        List<VulnerabilityScript> errorScriptsFromProgram = scriptExecutionPlan.getErrorScripts();

        assertNotNull(actual);
        assertEquals(0, actual.size());
        assertEquals(expectedSet, actual);
        assertEquals(expectedErrorScripts, errorScriptsFromProgram);
    }

    @Test
    void start_shouldGetExecutionPlan_whenLooping() {
        List<VulnerabilityScript> scripts = new ArrayList<>() {{
            add(new VulnerabilityScript(2, Arrays.asList(2)));
        }};

        when(storageMock.getScriptList()).thenReturn(scripts);

        HashSet<Integer> expectedSet = new LinkedHashSet<>();

        List<VulnerabilityScript> expectedErrorScripts = new ArrayList<>() {{
            add(new VulnerabilityScript(2, Arrays.asList(2)));
        }};

        Set<Integer> actual = scriptExecutionPlan.start();
        List<VulnerabilityScript> errorScriptsFromProgram = scriptExecutionPlan.getErrorScripts();

        assertNotNull(actual);
        assertEquals(0, actual.size());
        assertEquals(expectedSet, actual);
        assertEquals(expectedErrorScripts, errorScriptsFromProgram);
    }

    @Test
    void start_shouldGetExecutionPlan_whenScriptsIdNull() {
        List<VulnerabilityScript> scripts = new ArrayList<>() {{
            add(new VulnerabilityScript(null, List.of(2)));
            add(new VulnerabilityScript(2, List.of(3)));
            add(new VulnerabilityScript(3, new ArrayList<>()));
        }};

        when(storageMock.getScriptList()).thenReturn(scripts);

        HashSet<Integer> expectedSet = new LinkedHashSet<>() {{
            add(3);
            add(2);
        }};

        List<VulnerabilityScript> expectedErrorScripts = new ArrayList<>() {{
            add(new VulnerabilityScript(null, List.of(2)));
        }};

        Set<Integer> actual = scriptExecutionPlan.start();
        List<VulnerabilityScript> errorScriptsFromProgram = scriptExecutionPlan.getErrorScripts();

        assertNotNull(actual);
        assertEquals(2, actual.size());
        assertEquals(expectedSet, actual);
        assertEquals(expectedErrorScripts, errorScriptsFromProgram);
    }

    @Test
    void start_shouldGetExecutionPlan_whenThereAreNoSuchPeaksWithNull() {
        List<VulnerabilityScript> scripts = new ArrayList<>() {{
            add(new VulnerabilityScript(2, Arrays.asList(3, 4, null)));
        }};

        when(storageMock.getScriptList()).thenReturn(scripts);

        HashSet<Integer> expectedSet = new LinkedHashSet<>();

        List<VulnerabilityScript> expectedErrorScripts = new ArrayList<>() {{
            add(new VulnerabilityScript(2, Arrays.asList(3, 4, null)));
        }};

        Set<Integer> actual = scriptExecutionPlan.start();
        List<VulnerabilityScript> errorScriptsFromProgram = scriptExecutionPlan.getErrorScripts();

        assertNotNull(actual);
        assertEquals(0, actual.size());
        assertEquals(expectedSet, actual);
        assertEquals(expectedErrorScripts, errorScriptsFromProgram);
    }

    @Test
    void start_shouldGetExecutionPlan_whenThereAreNoSuchPeaks() {
        List<VulnerabilityScript> scripts = new ArrayList<>() {{
            add(new VulnerabilityScript(2, Arrays.asList(3, 4)));
        }};

        when(storageMock.getScriptList()).thenReturn(scripts);

        HashSet<Integer> expectedSet = new LinkedHashSet<>();

        List<VulnerabilityScript> expectedErrorScripts = new ArrayList<>() {{
            add(new VulnerabilityScript(2, Arrays.asList(3, 4)));
        }};

        Set<Integer> actual = scriptExecutionPlan.start();
        List<VulnerabilityScript> errorScriptsFromProgram = scriptExecutionPlan.getErrorScripts();

        assertNotNull(actual);
        assertEquals(0, actual.size());
        assertEquals(expectedSet, actual);
        assertEquals(expectedErrorScripts, errorScriptsFromProgram);
    }

    @Test
    void start_shouldGetExecutionPlan_whenExistsWithThreeScripts() {
        when(storageMock.getScriptList()).thenReturn(scripts);
        HashSet<Integer> expectedSet = new LinkedHashSet<>();
        expectedSet.add(4);
        expectedSet.add(2);
        expectedSet.add(1);

        Set<Integer> actual = scriptExecutionPlan.start();

        assertNotNull(actual);
        assertEquals(3, actual.size());
        assertEquals(expectedSet, actual);
    }

    @Test
    void start_shouldGetExecutionPlan_whenExistsWithTwoScripts() {
        List<VulnerabilityScript> scripts = Arrays.asList(
                new VulnerabilityScript(1, Collections.singletonList(2)),
                new VulnerabilityScript(2, Collections.emptyList())
        );
        when(storageMock.getScriptList()).thenReturn(scripts);

        Set<Integer> executionPlan = scriptExecutionPlan.start();

        Iterator<Integer> iterator = executionPlan.iterator();
        assertEquals(2, executionPlan.size());
        assertEquals(2, iterator.next());
        assertEquals(1, iterator.next());
    }

    @Test
    void start_shouldGetExecutionPlan_whenExistsWithNinetyNineScripts() {
        Storage storage = mock(Storage.class);
        ScriptExecutionPlan scriptExecutionPlan = new ScriptExecutionPlan(storage);
        List<VulnerabilityScript> scripts = Arrays.asList(
                new VulnerabilityScript(1, Arrays.asList(2, 3)),
                new VulnerabilityScript(2, Arrays.asList(4)),
                new VulnerabilityScript(3, Arrays.asList(5)),
                new VulnerabilityScript(4, Arrays.asList(6)),
                new VulnerabilityScript(5, Arrays.asList(7)),
                new VulnerabilityScript(6, Arrays.asList(8)),
                new VulnerabilityScript(7, Arrays.asList(9)),
                new VulnerabilityScript(8, Arrays.asList(10)),
                new VulnerabilityScript(9, Arrays.asList(11)),
                new VulnerabilityScript(10, Arrays.asList(12)),
                new VulnerabilityScript(11, Arrays.asList(13)),
                new VulnerabilityScript(12, Arrays.asList(14)),
                new VulnerabilityScript(13, Arrays.asList(15)),
                new VulnerabilityScript(14, Arrays.asList(16)),
                new VulnerabilityScript(15, Arrays.asList(17)),
                new VulnerabilityScript(16, Arrays.asList(18)),
                new VulnerabilityScript(17, Arrays.asList(19)),
                new VulnerabilityScript(18, Arrays.asList(20)),
                new VulnerabilityScript(19, Arrays.asList(21)),
                new VulnerabilityScript(20, Arrays.asList(22)),
                new VulnerabilityScript(21, Arrays.asList(23)),
                new VulnerabilityScript(22, Arrays.asList(24)),
                new VulnerabilityScript(23, Arrays.asList(25)),
                new VulnerabilityScript(24, Arrays.asList(26)),
                new VulnerabilityScript(25, Arrays.asList(27)),
                new VulnerabilityScript(26, Arrays.asList(28)),
                new VulnerabilityScript(27, Arrays.asList(29)),
                new VulnerabilityScript(28, Arrays.asList(30)),
                new VulnerabilityScript(29, Arrays.asList(31)),
                new VulnerabilityScript(30, Arrays.asList(32)),
                new VulnerabilityScript(31, Arrays.asList(33)),
                new VulnerabilityScript(32, Arrays.asList(34)),
                new VulnerabilityScript(33, Arrays.asList(35)),
                new VulnerabilityScript(34, Arrays.asList(36)),
                new VulnerabilityScript(35, Arrays.asList(37)),
                new VulnerabilityScript(36, Arrays.asList(38)),
                new VulnerabilityScript(37, Arrays.asList(39)),
                new VulnerabilityScript(38, Arrays.asList(40)),
                new VulnerabilityScript(39, Arrays.asList(41)),
                new VulnerabilityScript(40, Arrays.asList(42)),
                new VulnerabilityScript(41, Arrays.asList(43)),
                new VulnerabilityScript(42, Arrays.asList(44)),
                new VulnerabilityScript(43, Arrays.asList(45)),
                new VulnerabilityScript(44, Arrays.asList(46)),
                new VulnerabilityScript(45, Arrays.asList(47)),
                new VulnerabilityScript(46, Arrays.asList(48)),
                new VulnerabilityScript(47, Arrays.asList(49)),
                new VulnerabilityScript(48, Arrays.asList(50)),
                new VulnerabilityScript(49, Arrays.asList(51)),
                new VulnerabilityScript(50, Arrays.asList(52)),
                new VulnerabilityScript(51, Arrays.asList(53)),
                new VulnerabilityScript(52, Arrays.asList(54)),
                new VulnerabilityScript(53, Arrays.asList(55)),
                new VulnerabilityScript(54, Arrays.asList(56)),
                new VulnerabilityScript(55, Arrays.asList(57)),
                new VulnerabilityScript(56, Arrays.asList(58)),
                new VulnerabilityScript(57, Arrays.asList(59)),
                new VulnerabilityScript(58, Arrays.asList(60)),
                new VulnerabilityScript(59, Arrays.asList(61)),
                new VulnerabilityScript(60, Arrays.asList(62)),
                new VulnerabilityScript(61, Arrays.asList(63)),
                new VulnerabilityScript(62, Arrays.asList(64)),
                new VulnerabilityScript(63, Arrays.asList(65)),
                new VulnerabilityScript(64, Arrays.asList(66)),
                new VulnerabilityScript(65, Arrays.asList(67)),
                new VulnerabilityScript(66, Arrays.asList(68)),
                new VulnerabilityScript(67, Arrays.asList(69)),
                new VulnerabilityScript(68, Arrays.asList(70)),
                new VulnerabilityScript(69, Arrays.asList(71)),
                new VulnerabilityScript(70, Arrays.asList(72)),
                new VulnerabilityScript(71, Arrays.asList(73)),
                new VulnerabilityScript(72, Arrays.asList(74)),
                new VulnerabilityScript(73, Arrays.asList(75)),
                new VulnerabilityScript(74, Arrays.asList(76)),
                new VulnerabilityScript(75, Arrays.asList(77)),
                new VulnerabilityScript(76, Arrays.asList(78)),
                new VulnerabilityScript(77, Arrays.asList(79)),
                new VulnerabilityScript(78, Arrays.asList(80)),
                new VulnerabilityScript(79, Arrays.asList(81)),
                new VulnerabilityScript(80, Arrays.asList(82)),
                new VulnerabilityScript(81, Arrays.asList(83)),
                new VulnerabilityScript(82, Arrays.asList(84)),
                new VulnerabilityScript(83, Arrays.asList(85)),
                new VulnerabilityScript(84, Arrays.asList(86)),
                new VulnerabilityScript(85, Arrays.asList(87)),
                new VulnerabilityScript(86, Arrays.asList(88)),
                new VulnerabilityScript(87, Arrays.asList(89)),
                new VulnerabilityScript(88, Arrays.asList(90)),
                new VulnerabilityScript(89, Arrays.asList(91)),
                new VulnerabilityScript(90, Arrays.asList(92)),
                new VulnerabilityScript(91, Arrays.asList(93)),
                new VulnerabilityScript(92, Arrays.asList(94)),
                new VulnerabilityScript(93, Arrays.asList(95)),
                new VulnerabilityScript(94, Arrays.asList(96)),
                new VulnerabilityScript(95, Arrays.asList(97)),
                new VulnerabilityScript(96, Arrays.asList(98)),
                new VulnerabilityScript(97, Arrays.asList(99)),
                new VulnerabilityScript(98, new ArrayList<>()),
                new VulnerabilityScript(99, Arrays.asList(98))
        );
        when(storage.getScriptList()).thenReturn(scripts);

        Set<Integer> result = scriptExecutionPlan.start();

        assertEquals(99, result.size());
        assertTrue(result.contains(1));
        assertTrue(result.contains(2));
    }

    @Test
    void getMapFromScriptList_shouldGetKeyValueMap_whenProvidingVulnerabilityScript() {
        try {
            List<VulnerabilityScript> scripts = new ArrayList<>();
            scripts.add(new VulnerabilityScript(1, new ArrayList<>()));
            scripts.add(new VulnerabilityScript(2, new ArrayList<>()));
            scripts.add(new VulnerabilityScript(3, Arrays.asList(2, 1)));
            scripts.add(new VulnerabilityScript(4, Arrays.asList(3, 2)));
            Method getMapFromScriptList = ScriptExecutionPlan.class.getDeclaredMethod("getMapFromScriptList", List.class);
            getMapFromScriptList.setAccessible(true);

            List<KeyValueMap> result = (List<KeyValueMap>) getMapFromScriptList.invoke(scriptExecutionPlan, scripts);

            assertEquals(6, result.size());
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            e.printStackTrace();
        }
    }

    @Test
    void findLastValueOfScriptAndAddInExecutionPlan_shouldFindLastScripts_whenProvidingKeyValueMap() {
        try {
            List<KeyValueMap> keyValueMaps = new ArrayList<>();
            Map<Integer, Integer> map = new HashMap<>();
            map.put(0, 1);
            keyValueMaps.add(new KeyValueMap(1, map));
            Field executionPlanField = ScriptExecutionPlan.class.getDeclaredField("executionPlan");
            executionPlanField.setAccessible(true);
            Set<Integer> executionPlanSet = (Set<Integer>) executionPlanField.get(scriptExecutionPlan);
            executionPlanSet.add(2);
            Method findLastValueOfScriptAndPutInExecutionPlan = ScriptExecutionPlan.class.getDeclaredMethod("findLastValueOfScriptAndAddInExecutionPlan", List.class);
            findLastValueOfScriptAndPutInExecutionPlan.setAccessible(true);
            Set<Integer> expected = new LinkedHashSet<>();
            expected.add(2);
            expected.add(1);

            findLastValueOfScriptAndPutInExecutionPlan.invoke(scriptExecutionPlan, keyValueMaps);

            assertEquals(expected, executionPlanSet);
            assertEquals(2, executionPlanSet.size());
            assertEquals(2, executionPlanSet.iterator().next());
            assertTrue(executionPlanSet.contains(1));
            assertTrue(executionPlanSet.contains(2));
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void addSimpleValuesToExecutionPlan_shouldFindLastSimpleScripts_whenProvidingKeyValueMap() {
        try {
            List<KeyValueMap> keyValueMaps = new ArrayList<>();
            Map<Integer, Integer> map = new HashMap<>();
            map.put(2, 1);
            keyValueMaps.add(new KeyValueMap(1, map));
            Field executionPlanField = ScriptExecutionPlan.class.getDeclaredField("executionPlan");
            executionPlanField.setAccessible(true);
            Set<Integer> executionPlanSet = (Set<Integer>) executionPlanField.get(scriptExecutionPlan);
            executionPlanSet.add(2);
            Method findLastValueOfScriptAndPutInExecutionPlan = ScriptExecutionPlan.class.getDeclaredMethod("addSimpleValuesToExecutionPlan", List.class);
            findLastValueOfScriptAndPutInExecutionPlan.setAccessible(true);
            Set<Integer> expected = new LinkedHashSet<>();
            expected.add(2);
            expected.add(1);

            findLastValueOfScriptAndPutInExecutionPlan.invoke(scriptExecutionPlan, keyValueMaps);

            assertEquals(expected, executionPlanSet);
            assertEquals(2, executionPlanSet.size());
            assertEquals(2, executionPlanSet.iterator().next());
            assertTrue(executionPlanSet.contains(1));
            assertTrue(executionPlanSet.contains(2));
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void addDuplicateValuesToExecutionPlan_shouldFindDuplicateScripts_whenProvidingKeyValueMap() {
        try {
            List<KeyValueMap> keyValueMaps = new ArrayList<>();
            Map<Integer, Integer> map1 = new HashMap<>();
            map1.put(2, 2);
            Map<Integer, Integer> map2 = new HashMap<>();
            map2.put(3, 2);
            keyValueMaps.add(new KeyValueMap(1, map1));
            keyValueMaps.add(new KeyValueMap(1, map2));
            Field executionPlanField = ScriptExecutionPlan.class.getDeclaredField("executionPlan");
            executionPlanField.setAccessible(true);
            Set<Integer> executionPlanSet = (Set<Integer>) executionPlanField.get(scriptExecutionPlan);
            executionPlanSet.add(2);
            executionPlanSet.add(3);
            Method findLastValueOfScriptAndPutInExecutionPlan = ScriptExecutionPlan.class.getDeclaredMethod("addDuplicateValuesToExecutionPlan", List.class);
            findLastValueOfScriptAndPutInExecutionPlan.setAccessible(true);
            Set<Integer> expected = new LinkedHashSet<>();
            expected.add(2);
            expected.add(3);
            expected.add(1);

            findLastValueOfScriptAndPutInExecutionPlan.invoke(scriptExecutionPlan, keyValueMaps);

            assertEquals(expected, executionPlanSet);
            assertEquals(3, executionPlanSet.size());
            assertEquals(2, executionPlanSet.iterator().next());
            assertTrue(executionPlanSet.contains(1));
            assertTrue(executionPlanSet.contains(2));
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

}