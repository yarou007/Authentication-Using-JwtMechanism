package net.javaguides.springboot.controller;

import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.io.IOException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import net.javaguides.springboot.config.JwtService;
import net.javaguides.springboot.repository.UserRepository;
import net.javaguides.springboot.token.Token;
import net.javaguides.springboot.token.TokenRepository;
import net.javaguides.springboot.token.TokenType;
import net.javaguides.springboot.user.User;

import java.net.http.HttpHeaders;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
@Service
@RequiredArgsConstructor
public class AuthenticationService {

	@Autowired
	private final UserRepository userRepository ;
	
	@Autowired
	private final PasswordEncoder passwordEncoder;
	@Autowired 
	private final JwtService jwtService;
	@Autowired 
	private final TokenRepository tokenRepository;
	@Autowired
	final AuthenticationManager authenticationManager;


	// Create user save it databse and return generated token out of it 
	public AuthenticationResponse register(RegisterRequest request) {
		 var user = User.builder() 
			        .firstName(request.getFirstname())
			        .lastName(request.getLastname())
			        .email(request.getEmail())
			        .password(passwordEncoder.encode(request.getPassword()))
			        .role(request.getRole())
			        .build();
		 var savedUser = userRepository.save(user);
    	 var jwtToken = jwtService.generateToken(user);
    	 var refreshToken = jwtService.generateRefreshToken(user);
    	   saveUserToken(savedUser, jwtToken);
    	   return AuthenticationResponse.builder()
    	         .accessToken(jwtToken)
    	         .refreshToken(refreshToken)
    	        .build();
	}
	
	private void saveUserToken(User user, String jwtToken) {
		    var token = Token.builder()
		        .user(user)
		        .token(jwtToken)
		        .tokenType(TokenType.BEARER)
		        .expired(false)
		        .revoked(false)
		        .build();
		    tokenRepository.save(token);
		  }
	
	
	//
	public AuthenticationResponse authenticate (AuthenticationRequest request) {
		authenticationManager.authenticate(
		        new UsernamePasswordAuthenticationToken(
		            request.getEmail(),
		            request.getPassword()
		        )
		    );
		    var user = userRepository.findByEmail(request.getEmail())
		        .orElseThrow();
		    var jwtToken = jwtService.generateToken(user);
		    var refreshToken = jwtService.generateRefreshToken(user);
		   
		    return AuthenticationResponse.builder()
		        .accessToken(jwtToken)
		          	.refreshToken(refreshToken)
		        .build();
	}
	
	

}
