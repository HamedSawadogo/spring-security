package com.tp1_security.springjwtsecurity.controllers;
import com.tp1_security.springjwtsecurity.config.securityService.JWTService;
import com.tp1_security.springjwtsecurity.dao.UserDao;
import com.tp1_security.springjwtsecurity.model.IMuser;
import com.tp1_security.springjwtsecurity.model.User;
import com.tp1_security.springjwtsecurity.services.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

@Slf4j
@CrossOrigin("*")
@RestController
public class ApiController {

    private final UserDao userDao;
    private final JWTService jwtService;

    public ApiController(UserService userService, UserDao userDao, JWTService jwtService) {
        this.userDao = userDao;
        this.jwtService = jwtService;
    }
    @PreAuthorize("hasAuthority('SCOPE_ROLE_USER')")
    @GetMapping("/home")
    public String homePage(Authentication authentication){
        IMuser iMuser=userDao.findIMuserByUsername(authentication.getName());
        StringBuilder stringBuilder=new StringBuilder();
        stringBuilder.append("<p>Hi \uD83D\uDC4B Welcome, ").append(iMuser.getUsername()).append("</p>");
        stringBuilder.append("<strong>Messages:  </strong>");
        iMuser.getMessages().forEach(message -> {
            SimpleDateFormat simpleDateFormat=new SimpleDateFormat("dd-MM-yyyy");

            String date=simpleDateFormat.format(message.getCreatedDate());
            stringBuilder.append(message.getMessage());
            stringBuilder.append("</br>Date de creation: ").append(date);
        });
        return stringBuilder.toString();
    }

    @PostMapping("/login")
    public  Map<String, String> login(@RequestBody User user){
        if(user.password().isEmpty()||user.username().isEmpty())
            throw new NoSuchElementException("invalid password or username ");
        return this.jwtService.generateToken(user);
    }

    @GetMapping("/test")
    public String testPage(){
        return "test Message";
    }

    @PostAuthorize("hasAuthority('SCOPE_ROLE_USER')")
    @GetMapping("/")
    public String index(Authentication authentication){
        log.info(SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
        return "<h1>Home page ,Welcome  "+authentication.getName()+"!!!</h1>  "+ authentication;
    }

    @PostAuthorize("hasAuthority('SCOPE_ROLE_ADMIN')")
    @GetMapping("/admin")
    public String admin(){
        return "<h1>Welcome our Admin</h1>";
    }
}
