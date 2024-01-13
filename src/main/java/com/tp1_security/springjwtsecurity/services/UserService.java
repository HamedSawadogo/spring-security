package com.tp1_security.springjwtsecurity.services;
import com.tp1_security.springjwtsecurity.dao.MessageDao;
import com.tp1_security.springjwtsecurity.dao.UserDao;
import com.tp1_security.springjwtsecurity.model.IMuser;
import com.tp1_security.springjwtsecurity.model.Message;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Transactional
@Service
public class UserService {

    private final UserDao userDao;
    private final MessageDao messageDao;

    public UserService(UserDao userDao, MessageDao messageDao) {
        this.userDao = userDao;
        this.messageDao = messageDao;
    }

    public List<IMuser>getUsersList(){
        return userDao.findAll();
    }
    public void addMessageToUser(String username){
        IMuser user=userDao.findIMuserByUsername(username);
        Message message=new Message();
        message.setMessage("Well, you might be working on just the front end and you might have an API endpoint to get the JWT authToken and JWT refreshToken.\n" +
                "\n" +
                "let's create a new component to get the auth token. We will call it login.jsx and write the login-related logic here.\n" +
                "\n" +
                "In this file, we will have the signup method which takes username and password as payload and gets the authToken and RefreshToken\n" +
                "\n" +
                "Below is the code for the login component which is responsible for handling the login functionality");
        message.setCreatedDate(new Date());

        Message message1=messageDao.save(message);
        user.getMessages().add(message1);
    }
}

