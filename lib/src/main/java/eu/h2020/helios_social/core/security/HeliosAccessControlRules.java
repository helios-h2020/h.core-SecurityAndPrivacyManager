package eu.h2020.helios_social.core.security;

import java.io.Serializable;

public class HeliosAccessControlRules implements Serializable {
    private static final long serialVersionUID = 6524992348725128310L;
    private static final String TAG = "HeliosAccessControlRules";
    public String fileID;
    public HeliosAccessControlRulesTable rules;

    /**
     * Constructor for a HeliosAccessControlRules.
     *
     * @param fileID FileID that the rule concerns
     * @param rules the set of rules for the file
     */
    public HeliosAccessControlRules(String fileID, HeliosAccessControlRulesTable rules) {
        this.fileID = fileID;
        this.rules = rules;
    }

    @Override
    public String toString() {
        return "HeliosAccessControlRules{" +
                "fileID='" + fileID + '\'' +
                ", rules=" + rules.toString() +
                '}';
    }
}
