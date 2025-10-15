package com.bnaikcekr.parkr;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EnableJpaRepositories

@SpringBootApplication
public class ParkrAuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(ParkrAuthServiceApplication.class, args);
    }
}