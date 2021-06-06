package com.jwt.auth.controller;

import com.jwt.auth.model.JwtRequest;
import com.jwt.auth.model.JwtResponse;
import com.jwt.auth.service.UserService;
import com.jwt.auth.utility.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    UserService userService;

    @GetMapping("/")
    public String home(){
        return "welcome here ";
    }
    @PostMapping("/auth")
    public JwtResponse auth(@RequestBody JwtRequest jwtRequest) throws Exception {

        try{
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            jwtRequest.getName(),
                            jwtRequest.getPassword()
                    )
            );
            final UserDetails userDetails=userService.loadUserByUsername(jwtRequest.getName());
            final String jwtToken=jwtTokenUtil.generateToken(userDetails);
                return new JwtResponse(jwtToken);
        }catch (BadCredentialsException ex){

            throw new Exception("Invalid-Credentails",ex);
        }

    }

}
