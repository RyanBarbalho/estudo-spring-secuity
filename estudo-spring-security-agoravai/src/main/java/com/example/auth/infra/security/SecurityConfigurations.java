package com.example.auth.infra.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfigurations {
    final
    SecurityFilter securityFilter;

    public SecurityConfigurations(SecurityFilter securityFilter) {
        this.securityFilter = securityFilter;
    }

    //corrente de filtros que vou aplicar minha requisição pra autenticar o usuario
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {




        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable)//desabilitar csrf
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))//nao criar sessao no servidor
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()//permitir acesso a todos login
                        .requestMatchers(HttpMethod.POST, "/auth/register").permitAll()//permitir acesso a todos register,ideal é so admins serem permitidos
                        .requestMatchers(HttpMethod.POST, "/product").hasRole("ADMIN")//apenas admins podem criar produtos
                        .anyRequest().authenticated()//todas as outras requisiçoes devem estar autenticadas para serem acessadas
                )
                //fazer verificaçao do token
                .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager(); //pegar o authenticationManager do spring
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(); //classe que o spring fornece pra criptografar as senhas.
    }
}
