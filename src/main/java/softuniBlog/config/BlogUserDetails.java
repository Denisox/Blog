package softuniBlog.config;

import antlr.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import softuniBlog.entity.User;

import java.util.ArrayList;
import java.util.Collection;

public class BlogUserDetails extends User implements UserDetails {
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

    private ArrayList<String> roles;
    private User user;

    public BlogUserDetails(String email, String fullName, String password, ArrayList<String> roles, User user) {
        super(user.getEmail(), user.getFullName(), user.getPassword());
        this.roles = roles;
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        // Addition, check it out
        String userRoles = String.join(",", this.roles);
        return AuthorityUtils.commaSeparatedStringToAuthorityList(userRoles);

    }

    public User getUser(){
        return this.user;
    }


    // Addition, check it out
    public String getUsername(){
        return this.user.getEmail();
    }

}
