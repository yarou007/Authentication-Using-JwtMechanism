package net.javaguides.springboot.config;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import net.javaguides.springboot.user.User;

@Service
public class JwtService {

	  private static String SECRET_KEY ="4768517776714574456B7173764D623431336C36417538584B374B3475415744";
	  @Value("${application.security.jwt.expiration}")
	  private long jwtExpiration;
	  @Value("${application.security.jwt.refresh-token.expiration}")
	  private long refreshExpiration;

	
	public String generateToken(UserDetails userDetails) {
		return generateToken(new HashMap<>(), userDetails);
	}
	
	public String generateToken(
		      Map<String, Object> extraClaims,
		      UserDetails userDetails
		  ) {
		    return buildToken(extraClaims, userDetails, jwtExpiration);
		  }
	public String generateRefreshToken(
		      UserDetails userDetails
		  ) {
		    return buildToken(new HashMap<>(), userDetails, refreshExpiration);
		  }
	
	public String buildToken(
			Map<String , Object> extraClaims ,
			UserDetails userDetails,
			long expiration) {
		// extra claims map feha additional data aal users 
		// userDetails mao contains user data emsou aal jesmou 
		return Jwts
				.builder() // lancement taa generator token 
				.setClaims(extraClaims) // el data taa extra claims behs tetzed fil payload // accessible by the receiver 
				.setSubject(userDetails.getUsername()) // el sayed li besh nhotou fih el data 
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() +1000 * 60  * 24 ) )
				.signWith(getSignIngKey(), SignatureAlgorithm.HS256	)
				.compact(); // tarcha9 el token 
	}
	
	public String extractUsername(String token) {
	   return extractClaim(token, Claims::getSubject);
	}
	
	public boolean isTokenValid(String token,UserDetails userDetails) {
		final String username = extractUsername(token);
		
		return (username.equals(userDetails.getUsername()) && isTokenExpired(token));
	}
	public boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}
	
	public Date extractExpiration (String token) {
		return extractClaim(token, Claims::getExpiration);
	}
	private <T> T extractClaim (String token, Function<Claims, T> claimsResolver){
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
		
	}
	private Claims extractAllClaims(String token ) {
		
		return Jwts
				.parserBuilder() // hadhrtou besh yebni el jwt 
				.setSigningKey(getSignIngKey()) // aatitou l key besh yaaref li ena trust aamel aal tala aal next function to understand more 
				.build() // dyma build behs yekhdem khedmtou 
				.parseClaimsJws(token) /// traja3lek el jwt  
				.getBody(); // t'heé l body teek 
		// exemple 
		/*eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  --> Header*/ 
		/* .eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ. --> Payload
		 * SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  --> Signature 
		 */
	}	
	// besh traja3 l key li hashtek bih ( create it ) 
	private Key getSignIngKey() {
       byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY); // // making specialy key decoding / ciphering el secret key to 1's and 0's  
		// keyBytes heya special key moush secret key 
       
       return Keys.hmacShaKeyFor(keyBytes);  // behs nhotou fi lock sondou9 w ma yet7al ken bel secret key , kifeh ? stay tuned 
	}

}
