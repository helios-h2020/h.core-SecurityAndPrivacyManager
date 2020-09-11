package eu.h2020.helios_social.core.security;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;

public class HeliosAccessControlRulesTable implements Serializable {
    private static final String TAG = "HeliosAccessControlRulesTable";
    private static final long serialVersionUID = 6524992348725128311L;

    //not synchronized
    private ArrayList<String[]> table;

    /**
     * Constructor.
     */
    public HeliosAccessControlRulesTable() {
        table = new ArrayList<>();
    }

    /**
     * Add a rule to the table of rules
     * @param action the action the rule is about
     * @param ruling whether the action is ALLOWED or DENIED
     * @param actor userID or attribute of the actor
     * @param actorType type of actor is either USERID or EGONETWORKATTRIBUTE
     */
    public void add(String action, String ruling, String actor, String actorType){
        String[] rule = new String[4];
        rule[0]=action;
        rule[1]=ruling;
        rule[2]=actor;
        rule[3]=actorType;
        table.add(rule);
    }

    /**
     * Remove a rule from the table of rules. All four fields must mach. All matches are removed.
     * @param action the action the rule is about
     * @param ruling whether the action is ALLOWED or DENIED
     * @param actor userID or attribute of the actor
     * @param actorType type of actor is either USERID or EGONETWORKATTRIBUTE
     */
    public void remove(String action, String ruling, String actor, String actorType){
        Iterator itr = table.iterator();
        while (itr.hasNext())
        {
            String[] row = (String[]) itr.next();
            if (row[0].equals(action) && row[1].equals(ruling) && row[2].equals(actor) && row[3].equals(actorType))
                itr.remove();
        }
    }

    /**
     *  Gives the number of rules in the table
     * @return number of rules in the table
     */
    public int length() {
        return table.size();
    }

    /**
     * Return the action field of the i:th rule in the rule table.
     * @param i the number of the rule
     * @return the action of the rule
     */
    public String action(int i) {
        return table.get(i)[0];
    }

    /**
     * Return the ruling field of the i:th rule in the rule table.
     * @param i the number of the rule
     * @return the ruling of the rule. Either ALLOWED or DENIED.
     */
    public String ruling(int i) {
        return table.get(i)[1];
    }

    /**
     * Return the actor field of the i:th rule in the rule table.
     * @param i the number of the rule
     * @return the actor of the rule. Either fileID or attribute
     */
    public String actor(int i) {
        return table.get(i)[2];
    }

    /**
     * Return the type of the actor of the i:th rule in the rule table.
     * @param i the number of the rule
     * @return the type of the actor of the rule. Either USERID or EGONETWORKATTRIBUTE.
     */
    public String actorType(int i) {
        return table.get(i)[3];
    }

    @Override
    public String toString() {

        String temp = "";
        Iterator itr = table.iterator();
        while (itr.hasNext())
        {
            String[] row = (String[]) itr.next();
            temp += "action=" + row[0] + ", rule=" + row[1] + ", actor=" + row[2] + ", actorType="  + row[3] + "; ";
        }

        return "HeliosAccessControlRulesTable{" +
                "rules=" + temp +
                '}';
    }
}
