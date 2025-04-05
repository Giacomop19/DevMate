package com.onelife.devmate.service;

import com.onelife.devmate.dto.SignupDto;
import com.onelife.devmate.model.User;
import com.onelife.devmate.repository.RoleRepository;
import com.onelife.devmate.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthService {

    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public AuthService(
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            UserRepository userRepository
    ){
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
    }

    public void signup(SignupDto signupDto) {
        var userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new IllegalStateException("ROLE USER was not initialized"));

        var user = User.builder()
                .username(signupDto.getUsername())
                .email(signupDto.getEmail())
                .password(passwordEncoder.encode(signupDto.getPassword()))
                .roles(List.of(userRole))
                .build();
        this.userRepository.save(user);
    }

}
