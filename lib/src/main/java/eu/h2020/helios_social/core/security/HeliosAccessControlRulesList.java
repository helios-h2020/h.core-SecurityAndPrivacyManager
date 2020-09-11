package eu.h2020.helios_social.core.security;

import java.util.ArrayList;
import java.util.Iterator;

public class HeliosAccessControlRulesList {
    private static final String TAG = "HeliosAccessControlRulesList";
    private static HeliosAccessControlRulesList sInstance = new HeliosAccessControlRulesList();

    //not synchronized
    private ArrayList<HeliosAccessControlRules> mRulesForFiles;

    /**
     * Get instance of this class.
     *
     * @return an instance of the class
     */
    public static HeliosAccessControlRulesList getInstance() {
        return sInstance;
    }

    /**
     * Constructor.
     */
    public HeliosAccessControlRulesList() {
        mRulesForFiles = new ArrayList<>();
    }

    /**
     * Set access control rules for a file
     *
     * @param fileID     the fileID of the file
     * @param rulesTable the table of access control rules
     */
    public void addAccessRules(String fileID, HeliosAccessControlRulesTable rulesTable) {
        boolean found = false;
        for (HeliosAccessControlRules entry : mRulesForFiles) {
            if (entry.fileID.equals(fileID)) {
                found = true;
                entry.rules = rulesTable;
            }
        }
        if (!found) {
            HeliosAccessControlRules newRule = new HeliosAccessControlRules(fileID, rulesTable);
            mRulesForFiles.add(newRule);
        }
    }

    /**
     * Return the access control rule table for a file
     *
     * @param fileID the fileID of the file
     * @return the table of access control rules
     */
    public HeliosAccessControlRulesTable findAccessRules(String fileID) {
        for (HeliosAccessControlRules entry : mRulesForFiles) {
            if (entry.fileID.equals(fileID)) {
                return entry.rules;
            }
        }
        return null;
    }

    /**
     * Remove fileID and access control table from list
     *
     * @param fileID the fileID of the file
     */
    public void removeAccessRules(String fileID) {
        Iterator itr = mRulesForFiles.iterator();
        while (itr.hasNext()) {
            HeliosAccessControlRules entry = (HeliosAccessControlRules) itr.next();
            if (entry.fileID.equals(fileID))
                itr.remove();
        }
    }

    protected ArrayList<HeliosAccessControlRules> getRulesForFiles() {
        return mRulesForFiles;
    }

    protected void replaceAllRules(ArrayList<HeliosAccessControlRules> rules) {
        mRulesForFiles = rules;
    }
}
