package com.payfone.oauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication //(exclude = { SecurityAutoConfiguration.class })
public class AuthorizationApplication
{
    public static void main(String[] args)
    {
        SpringApplication.run(AuthorizationApplication.class, args);
    }
}