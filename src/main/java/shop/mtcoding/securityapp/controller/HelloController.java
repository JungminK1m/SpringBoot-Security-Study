package shop.mtcoding.securityapp.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import shop.mtcoding.securityapp.core.auth.MyUserDetails;
import shop.mtcoding.securityapp.core.jwt.MyJwtProvider;
import shop.mtcoding.securityapp.dto.ResponseDTO;
import shop.mtcoding.securityapp.dto.UserRequest;
import shop.mtcoding.securityapp.dto.UserResponse;
import shop.mtcoding.securityapp.model.User;
import shop.mtcoding.securityapp.model.UserRepository;
import shop.mtcoding.securityapp.service.UserService;

/*
 * 프로그램에는 로그 레벨이라는 것이 있다
 * 로그 레벨 : trace, debug, info, warn, error
 * 스프링의 기본 전력은 info 지만 개발할 때느 debug로 로그를 남기자!
 * 심각한 오류는 error 400/401/402..., 404같은 건 warn 경고체크 (나는 정상인데 지가 이상하게 주소 접근시도)
 * 
 */

@Slf4j
@RequiredArgsConstructor
@Controller
public class HelloController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;

    @Value("${meta.name}")
    private String name;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserRequest.LoginDTO loginDTO) {
        String jwt = userService.로그인(loginDTO);
        return ResponseEntity.ok().header(MyJwtProvider.HEADER, jwt).body("로그인 완료");
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<?> userCheck(
            @PathVariable Long id,
            @AuthenticationPrincipal MyUserDetails myUserDetails) {

        String username = myUserDetails.getUser().getUsername();
        String role = myUserDetails.getUser().getRole();
        return ResponseEntity.ok().body(username + " : " + role);
    }

    @GetMapping("/")
    public ResponseEntity<?> hello() {

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                "ssar",
                "1234");
        // UserDetails, password, authories
        Authentication authentication1 = authenticationManager.authenticate(authenticationToken);

        User user = userRepository.findByUsername("username").get();
        MyUserDetails myUserDetails = new MyUserDetails(user);
        Authentication authentication2 = new UsernamePasswordAuthenticationToken(
                myUserDetails,
                myUserDetails.getPassword(),
                myUserDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication2);

        return ResponseEntity.ok().body(name);
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @PostMapping("/join")
    public ResponseEntity<?> join(UserRequest.JoinDTO joinDTO) {
        // select 됨
        UserResponse.JoinDto data = userService.회원가입(joinDTO);
        // select 안됨
        ResponseDTO<?> responseDTO = new ResponseDTO<>().data(data);
        return ResponseEntity.ok().body(responseDTO);
    }
}
