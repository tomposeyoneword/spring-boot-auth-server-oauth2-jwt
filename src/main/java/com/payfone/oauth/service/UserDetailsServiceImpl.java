package com.payfone.oauth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService
{
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String inUserName) throws UsernameNotFoundException
    {
        //        User user = userRepository.findByUsername(username);
        //
        //        if(user == null) {
        //            throw new UsernameNotFoundException(String.format("The username %s doesn't exist", username));
        //        }
        //
        //        List<GrantedAuthority> authorities = new ArrayList<>();
        //        List<Role> roles = user.getRoles();
        //        for(Role role : roles){
        //            authorities.add(new SimpleGrantedAuthority(role.getName()));
        //        }

        //        UserDetails userDetails = new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
        //                authorities);

        String userName = "user_id";//user.getUsername();
        String userPassword = passwordEncoder.encode("user_pw");//user.getPassword();
        return new org.springframework.security.core.userdetails.User(
                userName,
                userPassword,
                AuthorityUtils.createAuthorityList("password"));
    }
}
