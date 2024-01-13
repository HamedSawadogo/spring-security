package com.tp1_security.springjwtsecurity.dao;
import com.tp1_security.springjwtsecurity.model.IMuser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserDao extends JpaRepository<IMuser,String> {
    IMuser findIMuserByUsername(String username);
}
