package com.example.auth.services;

import com.example.auth.repositories.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AuthorizationService implements UserDetailsService {

    final UserRepository userRepository;

    public AuthorizationService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override //sempre que algm se autenticar o spring security vai usar isso pra consultar
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //metodo vai consultar os usuarios pelo login e retornar um UserDetails
        return userRepository.findByLogin(username);
    }
}
