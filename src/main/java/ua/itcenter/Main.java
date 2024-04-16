package ua.itcenter;

import ua.itcenter.db.Storage;
import ua.itcenter.service.ScriptExecutionPlan;

public class Main {

    public static void main(String[] args) {
        ScriptExecutionPlan executionPlan = new ScriptExecutionPlan(new Storage());
        executionPlan.start();
    }

}
