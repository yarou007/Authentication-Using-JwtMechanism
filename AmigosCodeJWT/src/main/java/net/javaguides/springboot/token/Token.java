package net.javaguides.springboot.token;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.javaguides.springboot.repository.UserRepository;
import net.javaguides.springboot.user.User;

@Data
@Builder 
@NoArgsConstructor

@Entity
public class Token {

	  @Id
	  @GeneratedValue
	  public Integer id;

	  @Column(unique = true)
	  public String token;

	  @Enumerated(EnumType.STRING)
	  public TokenType tokenType = TokenType.BEARER;

	  public boolean revoked;

	  public boolean expired;

	  @ManyToOne(fetch = FetchType.LAZY)
	  @JoinColumn(name = "user_id")
	  public User user;

	public Token(Integer id, String token, TokenType tokenType, boolean revoked, boolean expired, User user) {
		super();
		this.id = id;
		this.token = token;
		this.tokenType = tokenType;
		this.revoked = revoked;
		this.expired = expired;
		this.user = user;
	}
	  
	  
}
