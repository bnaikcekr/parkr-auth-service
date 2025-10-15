package com.bnaikcekr.parkr.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ParkrUserRegisterDTO {
    private String email;
    private String username;
    private String password;
    private String firstName;
    private String lastName;
}
