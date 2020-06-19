package com.jmworks.auth.controller;

import com.jmworks.auth.payload.SignupRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/user")
public class UserController {

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public String getProfile(@PathVariable("id") String userId) {

        return "사용자 상세정보 조회 ... " + userId;
    }
}

