package shop.mtcoding.securityapp.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import shop.mtcoding.securityapp.core.jwt.JwtAuthorizationFilter;
import shop.mtcoding.securityapp.dto.ResponseDTO;

@Slf4j
@Configuration
public class SecurityConfig {

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // JWT 필터 등록이 필요함
    public class CustomSecurityFilterManager extends AbstractHttpConfigurer<CustomSecurityFilterManager, HttpSecurity> {
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
            builder.addFilterAt(new JwtAuthorizationFilter(authenticationManager), BasicAuthenticationFilter.class);
            super.configure(builder);
        }
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

        // 2. iframe 거부
        http.headers().frameOptions().disable();

        // 3. CORS 재설정
        http.cors().configurationSource(configurationSource());

        // 4. jsessionId 사용거부 (브라우저한테 jsessionId 전송안할거임, 세션을 안 쓴다는 말은 아님)
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // 5. form login 해제 (=csrf 필요없다는 뜻)
        // 해제하면 http basic 정책 때문에 알림창이 뜬다.
        http.formLogin().disable();

        // 6. httpBasic 정책 해제 (BasicAuthenticationFilter 해제)
        // http.httpBasic().disable();

        // 7. XXS (lucy 필터 - 네이버)
        // 네이버가 자바스크립트를 막기위한 보안 최종 결정체

        // 8. 커스텀 필터 적용하기 (시큐리티 필터를 내껄로 교환)
        http.apply(new CustomSecurityFilterManager());

        // 9. 시큐리티가 인증을 실패하거나 성공했을 때 success 핸들러를 썼었는데 이제 못씀
        // 인증 실패 처리
        http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
            // request.getRemoteAddr(); 요청들어온 IP 주소 <= 이걸 이용해 블랙리스트 처리도 가능
            // checkPoint -> 예외 핸들러 처리하기
            // 로그 확인하기
            log.debug("디버그 : 인증실패 : " + authException.getMessage());
            log.info("인포 : 인증실패 : " + authException.getMessage());
            log.warn("워닝 : 인증실패 : " + authException.getMessage());
            log.error("에러 : 인증실패 : " + authException.getMessage());

            response.setContentType("text/plain; chatset=utf-8");
            response.setStatus(401);
            response.getWriter().println("인증 실패");
        });

        // 10. 권한 실패 처리
        // 시큐리티는 언제 권한을 실패할까? role 처리가 안될 때
        http.exceptionHandling().accessDeniedHandler((request, response, accessDeniedHandler) -> {
            // checkPoint
            // 로그 확인하기
            log.debug("디버그 : 인증실패 : " + accessDeniedHandler.getMessage());
            log.info("인포 : 인증실패 : " + accessDeniedHandler.getMessage());
            log.warn("워닝 : 인증실패 : " + accessDeniedHandler.getMessage());
            log.error("에러 : 인증실패 : " + accessDeniedHandler.getMessage());

            response.setContentType("text/plain; chatset=utf-8");
            response.setStatus(403);
            response.getWriter().println("권한 실패");
        });

        // 3. 인증 권한 필터 설정
        http.authorizeRequests((authorize) -> authorize.antMatchers("/users/**")
                .authenticated()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/manager/**").access("hasRole('ADMIN') or hasRole('MANAGER')")
                .anyRequest().permitAll());

        return http.build();
    }

    public CorsConfigurationSource configurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*"); // GET, POST, PUT, DELETE (Javascript 요청 허용)
        configuration.addAllowedOriginPattern("*"); // 모든 IP 주소 허용 (프론트 앤드 IP만 허용 react)
        configuration.setAllowCredentials(true); // 클라이언트에서 쿠키 요청 허용
        configuration.addExposedHeader("Authorization"); // 옛날에는 디폴트 였다. 지금은 아닙니다.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
