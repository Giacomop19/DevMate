package com.onelife.devmate.util;

import com.onelife.devmate.service.UserDetailsSrv;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import lombok.extern.log4j.Log4j2;
import io.jsonwebtoken.*;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

import java.util.Date;


@Component
@Log4j2
public class JwtUtil {
    private final Environment env;
    private SecretKey jwtSecret;
    private Long jwtExpirationMs;
    //constructor
    @Autowired
    public JwtUtil(Environment env){
        this.env = env;
    }

    @PostConstruct
    public void init(){
        String secretKey = env.getProperty("devmate.prop.key");
        if(secretKey == null || secretKey.isEmpty()){
            throw new IllegalStateException("JWT Secret must be initialized");
        }
        jwtSecret = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

        String expirationMs = env.getProperty("devmate.prop.jwtExpiration");
        if (expirationMs == null) {
            throw new IllegalStateException("JWT Expiration time must be configured!");
        }
        jwtExpirationMs = Long.parseLong(expirationMs);

    }

    //@Value("${devmate.prop.jwtExpirationMs}")
    //private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication){
        UserDetailsSrv userPrincipal = (UserDetailsSrv) authentication.getPrincipal();
        return Jwts.builder().subject((userPrincipal.getUsername()))
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(jwtSecret, Jwts.SIG.HS512)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().verifyWith(jwtSecret).build().parseUnsecuredClaims(token).getPayload().getSubject();
    }

    public boolean validateJwtToken(String authToken){
        try {
            Jwts.parser().verifyWith(jwtSecret).build().parseUnsecuredClaims(authToken);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT Singature: {}", e.getMessage());
        }catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
