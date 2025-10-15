package com.bnaikcekr.parkr.service;

import com.bnaikcekr.parkr.model.ParkerUser;
import com.bnaikcekr.parkr.model.ParkerUserDetails;
import com.bnaikcekr.parkr.model.ParkrUserRegisterDTO;
import com.bnaikcekr.parkr.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Service
@RequiredArgsConstructor
@AllArgsConstructor
public class ParkrUserDetailService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<ParkerUser> user = userRepository.findByUsername(username);
        user.orElseThrow(() -> new UsernameNotFoundException("Not found: " + username));
        return user.map(ParkerUserDetails::new).get();
    }

    public ParkerUserDetails registerUser(ParkrUserRegisterDTO userRegisterDTO) {
        AtomicReference<ParkerUserDetails> userDetails = new AtomicReference<>();
        userRepository.findByUsername(userRegisterDTO.getUsername()).ifPresentOrElse(
                existingUser -> {
                    log.error("User already exists: " + existingUser.getUsername());
                },
                () -> {
                    ParkerUser user = convertToParkerUser(userRegisterDTO);
                    ParkerUser savedUser = userRepository.save(user);
                    userDetails.set(new ParkerUserDetails(savedUser));
                }
        );

        return userDetails.get();
    }

    public List<ParkerUser> getAllUsers(){
        List<ParkerUser> detailsList = new ArrayList<>();
        userRepository.findAll().forEach(detailsList::add);

        return  detailsList;
    }

    public void deleteUser(String username){
        userRepository.deleteById(username);
    }

    // utilities
    public ParkerUser convertToParkerUser(ParkrUserRegisterDTO parkUserRegisterDTO) {
        return ParkerUser.builder()
                .id(UUID.randomUUID().toString())
                .username(parkUserRegisterDTO.getUsername())
                .password(passwordEncoder.encode(parkUserRegisterDTO.getPassword()))
                .email(parkUserRegisterDTO.getEmail())
                .firstName(parkUserRegisterDTO.getFirstName())
                .lastName(parkUserRegisterDTO.getLastName())
                .phoneNumber("")
                .permissions(0)
                .sessionID(UUID.randomUUID().toString())
                .userLastIPAddress("")
                .userLastLoginDateTime(ZonedDateTime.now().toString())
                .deviceID("")
                .roles(Collections.singletonList("admin"))
                .enabled(true)
                .build();
    }

}
