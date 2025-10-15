package com.bnaikcekr.parkr.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class ParkerUser {
    @Id
    private String id;
    private String username;
    private String password;
    private String email;
    private int permissions;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String sessionID;
    private String userLastIPAddress;
    private String userLastLoginDateTime;
    private String deviceID;
    private List<String> roles;
    private boolean enabled;

}
