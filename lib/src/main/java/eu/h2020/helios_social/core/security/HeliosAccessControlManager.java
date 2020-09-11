package eu.h2020.helios_social.core.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.*;

public class HeliosAccessControlManager {
    private static final String TAG = "HeliosAccessControlManager";
    private static HeliosAccessControlRulesList mAccessControlRulesList = HeliosAccessControlRulesList.getInstance();
    private static HeliosAccessControlManager ourInstance = new HeliosAccessControlManager();

    /* Location of the policy repository */
    private String mFileBaseDir = "";
    private static final String AC_FILENAME = "helios.ac";
    private static final String RULE_DIR = "ac";
    // Rule properties
    public static final String ALLOWED = "allowed";
    public static final String DENIED = "denied";
    public static final String USERID = "userID";
    public static final String EGONETWORKATTRIBUTE = "egonetworkattribute";

    /**
     * Get the singleton instance of this Manager.
     *
     * @return {@link HeliosAccessControlManager}
     */
    public static HeliosAccessControlManager getInstance() {
        return ourInstance;
    }

    /**
     * Init required for storing base dir.
     * @param ruleBaseDir Base directory to store the rule files.
     */
    public void init(final String ruleBaseDir) {
        // Save the base directory for storing rules.
        mFileBaseDir = ruleBaseDir;

        // Create directory if not existing
        File base = new File(mFileBaseDir, RULE_DIR);

        if (!base.exists()) {
            System.out.println("Rule directory does not exist, creating.");

            boolean created = base.mkdir();
            if (!created) {
                System.out.println("Rule directory creation failed.");
            }
        } else{
            // Default for now, load rules after init if exists
            loadAllRules();
        }
    }

    /**
     * Check if the subject is allowed to perform the action with the object
     *
     * @param fileID The ID of the object
     * @param action The action the subject wants to perform with the object
     * @param userID The ID of the subject
     * @return true, if access is granted, false otherwise.
     * If there is a rule to deny action for user return false
     * ElseIf there is a rule to allow action for user return true
     * ElseIF there is a rule to deny action for user's attribute return false
     * ElseIF there is a rule to allow action for user's attribute return true
     * Else return false
     */
    public boolean requestAccess(String fileID, String action, String userID){
        HeliosAccessControlRulesTable rulesTable = mAccessControlRulesList.findAccessRules(fileID);
        if (rulesTable == null)
            return false;
        for (int row=0; row < rulesTable.length(); row++){
            if (rulesTable.action(row).equals(action) && rulesTable.ruling(row).equals(DENIED) && rulesTable.actor(row).equals(userID) && rulesTable.actorType(row).equals(USERID)) {
                return false;
            }
        }
        for (int row=0; row < rulesTable.length(); row++){
            if (rulesTable.action(row).equals(action) && rulesTable.ruling(row).equals(ALLOWED) && rulesTable.actor(row).equals(userID) && rulesTable.actorType(row).equals(USERID)) {
                return true;
            }
        }
        String[] attributeList = {"testattribute"}; /* getAttributesOfUserID(userID); */
        for (int row=0; row < rulesTable.length(); row++) {
            for (String attribute : attributeList) {
                if (rulesTable.action(row).equals(action) && rulesTable.ruling(row).equals(DENIED) && rulesTable.actor(row).equals(attribute) && rulesTable.actorType(row).equals(EGONETWORKATTRIBUTE)) {
                    return false;
                }
            }
        }
        for (int row=0; row < rulesTable.length(); row++) {
            for (String attribute : attributeList) {
                if (rulesTable.action(row).equals(action) && rulesTable.ruling(row).equals(ALLOWED) && rulesTable.actor(row).equals(attribute) && rulesTable.actorType(row).equals(EGONETWORKATTRIBUTE)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Sets a access control rule table for a file.
     * The rules are of type {action,ruling,userID,USERID}
     * or {action,ruling,attribute,EGONETWORKATTRIBUTE} and deny/grant access for
     * action to users with mentioned userID or attribute.
     *
     * @param fileID The object of the access policy
     * @param rulesTable the list of rules for the object
     */
    public void setAccessRules(String fileID, HeliosAccessControlRulesTable rulesTable) {
        if (rulesTable == null)
            mAccessControlRulesList.removeAccessRules(fileID);
        else
            mAccessControlRulesList.addAccessRules(fileID, rulesTable);
    }

    /**
     * Gets the table of access control rules for a file
     * The rules are of type {action,userID,"userID"}
     * or {action,attribute,"egonetworkattribute"} and grant access for
     * action to users with mentioned userID or attribute.
     *
     * @param fileID The object of the access policy
     * @return The array of rules for the object
     */
    public HeliosAccessControlRulesTable getAccessRules(String fileID) {
        return mAccessControlRulesList.findAccessRules(fileID);
    }

    /**
     * Load saved rules from a file and replace all current rules in accessControlRulesList.
     */
    public void loadAllRules(){
        //TODO decryption of rules file

        String rulesLocation = mFileBaseDir + File.separator + RULE_DIR + File.separator + AC_FILENAME;
        //System.out.println("rulesLocation:" + rulesLocation);
        try {
            FileInputStream f = new FileInputStream(rulesLocation);
            ObjectInputStream o = new ObjectInputStream(f);
            Object obj = o.readObject();
            ArrayList<HeliosAccessControlRules> rules = (ArrayList<HeliosAccessControlRules>) obj;

            // TEMP PRINT
            System.out.println("Rules loaded:" + rules.toString());
            for(HeliosAccessControlRules entry: rules) {
                System.out.println("ruleEntry.toString: " + rules.toString());
            }

            mAccessControlRulesList.replaceAllRules(rules);
        } catch (ClassNotFoundException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Save current rules to a file.
     */
    public void saveAllRules(){
        //TODO encryption of rules file

        // Rest of init actions
        String rulesLocation = mFileBaseDir + File.separator + RULE_DIR;

        File file = new File(rulesLocation, AC_FILENAME);
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        FileOutputStream out = null;
        try {
            out = new FileOutputStream(file);
            ObjectOutputStream oos = new ObjectOutputStream(out);
            oos.writeObject(mAccessControlRulesList.getRulesForFiles());
            oos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
