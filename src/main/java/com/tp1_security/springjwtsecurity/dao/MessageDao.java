package com.tp1_security.springjwtsecurity.dao;
import com.tp1_security.springjwtsecurity.model.Message;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MessageDao extends JpaRepository<Message,Integer> {
}
