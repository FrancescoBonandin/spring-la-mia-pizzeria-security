package org.java.spring.auth.conf;

import org.java.spring.auth.db.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AuthConfiguration {
	
	 @Bean
	    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			
			http.authorizeHttpRequests()
				.requestMatchers("/*/*/*/edit/**").hasAuthority("ADMIN")
				.requestMatchers("/*/*/*/create").hasAuthority("ADMIN")
		        .requestMatchers("*/create").hasAuthority("ADMIN")
		        .requestMatchers("*/edit/**").hasAuthority("ADMIN")
		        .requestMatchers("*/delete/**").hasAuthority("ADMIN")
		        .requestMatchers("/**").hasAnyAuthority("USER","ADMIN")
		        .and().formLogin()
		        .and().logout()
		        .and().csrf().disable();
		        
		    ;
			
			
			return http.build();
		}
	 
	 @Bean
	    UserDetailsService userDetailsService() {
		    return new UserService();
		}
	    
	    @Bean
		public static PasswordEncoder passwordEncoder() {
	      return new BCryptPasswordEncoder();
	    }
	    
	    @Bean
	    DaoAuthenticationProvider authenticationProvider() {
	      
	    	DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
	   
	    	authProvider.setUserDetailsService(userDetailsService());
	    	authProvider.setPasswordEncoder(passwordEncoder());
	   
	    	return authProvider;
	    }
	   

}
