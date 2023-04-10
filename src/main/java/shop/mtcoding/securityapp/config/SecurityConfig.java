package shop.mtcoding.securityapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 1. CSRF 해제
        http.csrf().disable(); // postman 접근해야 함! - CSR 할때!
        /*
         * csrf 가 뭐냐면!
         * 다른 사이트에서 공격하는거!를 막아줌
         * 막으려면 사이트마다 고유 토큰을 만들어야함
         */

        // 2. Form 로그인 설정
        http.formLogin()
                .loginPage("/loginForm")
                // name값 custom 가능
                .usernameParameter("username")
                .passwordParameter("password")
                .loginProcessingUrl("/login") // 얘는 무조건 POST + x-www-Form-urlEncoded
                .defaultSuccessUrl("/")
                .successHandler((req, resp, authentication) -> {
                    System.out.println("디버그 : 로그인이 완료되었습니다.");
                    resp.sendRedirect("/");

                })
                .failureHandler((req, resp, ex) -> {
                    System.out.println("디버그 : 로그인에 실패하였습니다 -> " + ex.getMessage());
                });

        // 3. 인증 권한 필터 설정
        http.authorizeRequests((authorize) -> authorize.antMatchers("/users/**")
                .authenticated()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/manager/**").access("hasRole('ADMIN') or hasRole('MANAGER')")
                .anyRequest().permitAll());

        return http.build();
    }
}
