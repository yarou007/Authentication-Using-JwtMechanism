package net.javaguides.springboot.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController 
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class Controller {
 
	
	@Autowired
	private final AuthenticationService service ;
	
	@PostMapping("/register")
	// besh ysajel behs taadilou RegisterRequest type ( donneés teeou l kol w mapped by RequestBody , behs yabeeth lil register w ysajem 
	// AuthenticationResponse behs trajaa ye access token ye refrech token w el entity 
	
	public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request){
		return ResponseEntity.ok(service.register(request));
		
	}
	
	@PostMapping("/authenticate")
	// AuthenticationRequest behs y login bel email w el mdp khw w yaamel liaison bel RequestBody kif laada 
	// ykamel yetaada yaamel athenticate 
	
	public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
		return ResponseEntity.ok(service.authenticate(request));

	}
}
