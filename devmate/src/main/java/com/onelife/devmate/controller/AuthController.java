package com.onelife.devmate.controller;

import com.onelife.devmate.dto.JwtResponse;
import com.onelife.devmate.dto.LoginDto;
import com.onelife.devmate.dto.SignupDto;
import com.onelife.devmate.repository.PersonRepository;
import com.onelife.devmate.service.AuthService;
import com.onelife.devmate.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("auth")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
    private final JwtUtil jwtUtil;
    private final AuthService authService;

    public AuthController(PersonRepository personRepository,
                          AuthenticationManager authenticationManager,
                          JwtUtil jwtUtil,
                          AuthService authService) {

        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid LoginDto loginDto) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtil.generateJwtToken(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        JwtResponse res = new JwtResponse();
        res.setToken(jwt);

        res.setUsername(userDetails.getUsername());
        res.setRoles(roles);
        return ResponseEntity.ok(res);
    }

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody @Valid SignupDto signupDto) {
        try{
            authService.signup(signupDto);
            return ResponseEntity.ok("User registered success");
        }catch (Exception e){
            log.error("Cannot signup: {}", e.getMessage());
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body("Cannot signup: " + e.getMessage());
        }
    }

    @PostMapping("/logout")
    public String logout(Authentication auth, HttpServletResponse response, HttpServletRequest request){
        this.logoutHandler.logout(request, response, auth);
        return "Logout successfully";
    }


}
