package org.jenkinsci.plugins.api;

import hudson.security.SecurityRealm;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;

public class RedmineUser implements UserDetails {

    public class RedmineUserResponce {
        public RedmineUser user;
    }

    public String login;
    public String firstname;
    public String lastname;
    public String mail;

    public RedmineUser() {
        super();
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return new GrantedAuthority[] { SecurityRealm.AUTHENTICATED_AUTHORITY };
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return this.login;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
