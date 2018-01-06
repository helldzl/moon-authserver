package org.moonframework.authorization.service;

import org.moonframework.authorization.domain.ApplicationUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // TODO find user by username from DB
        // passwordEncoder.encode("123");
        // password : 123
        ApplicationUser user = new ApplicationUser(username, "$2a$04$8NrNVkxWANsoXTAck8nA2exln1Xoxag3XB8aiF5eMnXot5TO6asDW", true, true, true, true, permissions());
        user.setId(11L);
        return user;
    }

    private Collection<? extends GrantedAuthority> permissions() {
        List<GrantedAuthority> list = new ArrayList<>();
        list.add(new SimpleGrantedAuthority("ROLE_USER"));
        list.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        list.add(new SimpleGrantedAuthority("ROLE_FORUM"));
        list.add(new SimpleGrantedAuthority("AUTH_1"));
        list.add(new SimpleGrantedAuthority("AUTH_2"));
        return list;
    }

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException {
        BCryptPasswordEncoder e = new BCryptPasswordEncoder(4, SecureRandom.getInstance("SHA1PRNG", "SUN"));
        System.out.println(e.encode("123"));
    }

}
