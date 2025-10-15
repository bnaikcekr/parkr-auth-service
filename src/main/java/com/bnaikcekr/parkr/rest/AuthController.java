package com.bnaikcekr.parkr.rest;

import com.bnaikcekr.parkr.model.ParkerUser;
import com.bnaikcekr.parkr.model.ParkerUserDetails;
import com.bnaikcekr.parkr.model.ParkrUserAuthDTO;
import com.bnaikcekr.parkr.model.ParkrUserRegisterDTO;
import com.bnaikcekr.parkr.service.ParkrUserDetailService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@RestController
public class AuthController {

    private final ParkrUserDetailService parkrUserDetailService;
    private final AuthenticationManager authManager;

//    private static final long EXPIRATION = 3600; // 1 hour
    private static final long EXPIRATION = 300; // 5 minutes
    private static final SecretKey SECRET = Keys.secretKeyFor(SignatureAlgorithm.HS512); // 1 hour

    private Map<String, String> authTokenMap = new ConcurrentHashMap<>(); // In-memory storage for tokens

    @GetMapping("/auth")
    public String authUser() {
        return "Hello, this is a test endpoint for authentication!";
    }

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
                return generateToken(authentication);
            });

            Jwt jwt = Jwts.parser().verifyWith(SECRET).build().parse(token);
            if( !((Claims)jwt.getPayload()).getExpiration().after(new Date())) {
                log.info("Token expired for user: {} - generating new token", creds.getUsername());
                authTokenMap.replace(authentication.getName(), token, generateToken(authentication));
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

    //utility method to get the token for a user
    private String generateToken(Authentication authentication) {
        Long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(authentication.getName())
                // Convert to list of strings.
                // This is important because it affects the way we get them back in the Gateway.
                .claim("authorities", authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + EXPIRATION * 1000))  // in milliseconds
                .signWith(SECRET)
                .compact();
    }

}

