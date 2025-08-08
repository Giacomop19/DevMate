package com.onelife.devmate.service;

import com.onelife.devmate.dto.SignupDto;
import com.onelife.devmate.model.Person;
import com.onelife.devmate.repository.RoleRepository;
import com.onelife.devmate.repository.PersonRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthService {

    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final PersonRepository personRepository;

    public AuthService(
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            PersonRepository personRepository
    ){
        this.personRepository = personRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
    }

    public void signup(SignupDto signupDto) {
        var userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new IllegalStateException("ROLE USER was not initialized"));
        if(personRepository.existsByEmail(signupDto.getEmail())){
            throw new RuntimeException("User email already exists");
        }

        var user = Person.builder()
                .username(signupDto.getUsername())
                .email(signupDto.getEmail())
                .password(passwordEncoder.encode(signupDto.getPassword()))
                .roles(List.of(userRole))
                .enabled(true)
                .build();
        this.personRepository.save(user);
    }

}
