package net.javaguides.springboot.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;


@Service // heya bid'ha Repository annotation li zouz ye'extendiw mel componenet annotation 
@Builder
@AllArgsConstructor


public class JWTAthenticationFilter extends OncePerRequestFilter{

	@Autowired
	private final JwtService jwtService;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	
	
	@Override 
	protected void doFilterInternal(@NonNull HttpServletRequest request,
			@NonNull HttpServletResponse response,
			@NonNull FilterChain filterChain)
			throws ServletException, IOException {
		final String authHeader = request.getHeader("Authorization"); // exemple nom de var = "Authorization": Bearer <token>
		final String jwt;
		final String userEmail;
		if (authHeader== null  || !authHeader.startsWith("Bearer") ) {
			filterChain.doFilter(request, response);
			return; 
		}
		jwt = authHeader.substring(7); // li mbaad el Bearer l kol ... 
		//Extract the userEmail token ;
		userEmail = jwtService.extractUsername(jwt); // kharjana l userEmail
		if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) { // check him out fil db && ken mahoush identifie w maamlesh connexion
			UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail) ;  // loadih
			if(jwtService.isTokenValid(jwt, userDetails)) { 
				// token valid ? 
				//instanciation taa authToken
            		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities()); 
           	     // userDetails ( objet ) // null howa el credentials /// 3éme param houma granted authorities 
			authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			// update security context holder 
			SecurityContextHolder.getContext().setAuthentication(authToken);
			}
			filterChain.doFilter(request, response);
		}
		
	}


}
