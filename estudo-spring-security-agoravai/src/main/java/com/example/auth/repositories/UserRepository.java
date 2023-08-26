package com.example.auth.repositories;

import com.example.auth.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    //consultar os usuarios pelo login
    User findByLogin(String login);


}
