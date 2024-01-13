package com.tp1_security.springjwtsecurity.config.securityService;
import com.tp1_security.springjwtsecurity.model.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@Slf4j
@Service
public class JWTService {

    private final JwtEncoder jwtEncoder;
    private final AuthenticationManager authenticationManager;

    public JWTService(JwtEncoder jwtEncoder, AuthenticationManager authenticationManager) {
        this.jwtEncoder = jwtEncoder;
        this.authenticationManager = authenticationManager;
    }
    /**
     * Méthode de génération du Token  d'authentification
     * @param user
     * @return
     */
    public Map<String,String> generateToken(User user){


       Authentication authentication=authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.username(),user.password())
        );
        String scope=authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));

        Instant now=Instant.now();
        JwtClaimsSet claims=JwtClaimsSet.builder()
                        .expiresAt(now.plus(10,ChronoUnit.HOURS))
                                .issuedAt(now)
                .subject(authentication.getName())
                .claim("scope",scope)
                .issuer("self")
                .build();

        JwtEncoderParameters jwtEncoderParameters=JwtEncoderParameters
                .from(JwsHeader.with(MacAlgorithm.HS256).build(),claims);

        return Map.of("access-token",this.jwtEncoder.encode(jwtEncoderParameters).getTokenValue());
    }
}
