package org.jenkinsci.plugins.api;

import net.sf.json.JSONObject;

public class RedmineUserResponse {
    public RedmineUser user;

    public static RedmineUserResponse fromJsonString(String string) {
        return (RedmineUserResponse) JSONObject.fromObject(string).toBean(RedmineUserResponse.class);
    }
}
