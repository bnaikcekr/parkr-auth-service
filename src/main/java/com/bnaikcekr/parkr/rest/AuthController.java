package com.bnaikcekr.parkr.rest;

import com.bnaikcekr.parkr.config.SecurityConfig;
import com.bnaikcekr.parkr.model.ParkerUser;
import com.bnaikcekr.parkr.model.ParkerUserDetails;
import com.bnaikcekr.parkr.model.ParkrUserAuthDTO;
import com.bnaikcekr.parkr.model.ParkrUserRegisterDTO;
import com.bnaikcekr.parkr.service.ParkrUserDetailService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@RestController
public class AuthController {

    private final ParkrUserDetailService parkrUserDetailService;
    private final AuthenticationManager authManager;
    private final JwtEncoder jwtEncoder;

//    private static final long EXPIRATION = 3600; // 1 hour
    private static final long EXPIRATION = 300; // 5 minutes
    private static final SecretKey SECRET = Keys.secretKeyFor(SignatureAlgorithm.HS512); // 1 hour

    private Map<String, String> authTokenMap = new ConcurrentHashMap<>(); // In-memory storage for tokens

    @GetMapping("/unsecured-endpoint")
    public String authUser() {
        return "Hello, this is a test endpoint for authentication!";
    }

    @GetMapping("/secured-endpoint")
    public String getSecuredResource(@RequestHeader("Authorization") String authToken) {
        // authToken will contain the full header value, e.g., "Bearer eyJhbGci..."
        // You might need to extract the actual token part if it's a Bearer token
        String actualToken = authToken.replace("Bearer ", "");

        // Now you can process the 'actualToken' for validation or other purposes
        log.info("Received Auth Token: {}", actualToken);

        return "Access granted with token: " + actualToken;
    }

    @GetMapping("/token")
    public Token getToken(JwtAuthenticationToken jwtToken) {
        return new Token(
                jwtToken.getToken(),
                jwtToken.getAuthorities()
        );
    }
    public record Token(org.springframework.security.oauth2.jwt.Jwt token, Collection<GrantedAuthority> authorities){}

    @PostMapping("/auth")
    public ResponseEntity<ParkrUserAuthDTO> authenticate(@RequestBody ParkerUserDetails creds) throws Exception {
        // 1. Get credentials from request

        // 2. Create auth object (contains credentials) which will be used by auth manager
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                creds.getUsername(), creds.getPassword(), Collections.emptyList());

        // 3. Authentication manager authenticate the user, and use UserDetialsServiceImpl::loadUserByUsername() method to load the user.
        try {
            Authentication authentication = authManager.authenticate(authToken);

            // 4. If authentication is successful, generate JWT token
            String token  = authTokenMap.computeIfAbsent(authentication.getName(), k -> {
                log.info("Token generated for user: {}", creds.getUsername());
                return generateJwtToken(authentication);
            });

            try {
                Jwt jwt = Jwts.parser().verifyWith(SecurityConfig.SECRET_KEY_PAIR.getPublic()).build().parse(token);
            } catch (ExpiredJwtException expiredJwtException){
                log.warn("Token expired for user: {} - generating new token", creds.getUsername());
                authTokenMap.replace(authentication.getName(), token, generateJwtToken(authentication));
            }

            // Add token to header
            log.info("Authentication successful for user: {}", creds.getUsername());
            ParkrUserAuthDTO userDTO = ParkrUserAuthDTO.builder()
                    .username(authentication.getName())
                    .roles(authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                    .enabled(authentication.isAuthenticated())
                    .build();
            return ResponseEntity.ok()
                    .header("Authorization", "Bearer " + token)
                    .body(userDTO);
        } catch (Exception ex) {
            log.error("Authentication failed for user: {}", creds.getUsername(), ex);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

    }

    @PostMapping("/register")
    public ResponseEntity<ParkerUserDetails> registerUser(@RequestBody ParkrUserRegisterDTO parkrUser) {
        ParkerUserDetails parkerUserDetails = parkrUserDetailService.registerUser(parkrUser);
        if (parkerUserDetails == null) {
            return ResponseEntity.badRequest().body(null);
        }
        log.info("User registered successfully: {}", parkerUserDetails.getUsername());
        return ResponseEntity.ok(parkerUserDetails);
    }

    //TODO: RESTRICT ACCESS
    @GetMapping("/users")
    public ResponseEntity<List<ParkerUser>> getAllUsers() {
        List<ParkerUser> users = parkrUserDetailService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    //TODO: RESTRICT ACCESS
    @DeleteMapping("/user/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable String userId){
        parkrUserDetailService.deleteUser(userId);
        return ResponseEntity.ok().build();
    }

    public String generateJwtToken(Authentication authentication) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://parkr.bnaikcekr.com")
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.MINUTES))
                .subject(authentication.getName())
                .claim("authorities", authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .build();

        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}

