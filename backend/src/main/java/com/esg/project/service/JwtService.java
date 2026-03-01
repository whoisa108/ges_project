package com.esg.project.service;

import com.esg.project.model.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service
public class JwtService {
    @Value("${jwt.secret}") private String secret;
    @Value("${jwt.expiration}") private long expiration;

    private Key getSigningKey() { return Keys.hmacShaKeyFor(secret.getBytes()); }

    public String generateToken(User user) {
        return Jwts.builder()
                .setSubject(user.getEmployeeId())
                .claim("role", user.getRole())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractEmployeeId(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    public boolean isTokenValid(String token) {
        try { Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token); return true; }
        catch (Exception e) { return false; }
    }
}
