package com.cos.jwt.repository;

import com.cos.jwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    // findBy 규칙 -> Username 문법
    // select * from user where username = ?
    public User findByUsername(String username);

}
