package com.tp1_security.springjwtsecurity.config.securityService;
import com.tp1_security.springjwtsecurity.dao.UserDao;
import com.tp1_security.springjwtsecurity.model.IMuser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserDao userDao;

    public UserDetailsServiceImpl(UserDao userDao) {
        this.userDao = userDao;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        IMuser user=userDao.findIMuserByUsername(username);
        return new User(user.getUsername(),user.getPassword(),user.getAuthorities());
    }
}
