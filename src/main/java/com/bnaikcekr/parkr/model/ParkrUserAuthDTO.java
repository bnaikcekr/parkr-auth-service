package com.bnaikcekr.parkr.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ParkrUserAuthDTO {
    private String username;
    private List<String> roles;
    private boolean enabled;
}
