package shop.mtcoding.securityapp.dto;

import lombok.Getter;
import lombok.Setter;
import shop.mtcoding.securityapp.core.util.MyDateUtils;
import shop.mtcoding.securityapp.model.User;

public class UserResponse {

    @Getter
    @Setter
    public static class JoinDto {
        private Long id;
        private String username;
        private String email;
        private String role;
        private String CreatedAt; // String인 것에 주의!!! 어차피 통신은 문자열

        // 응답은 무조건 생성자 만들기!
        public JoinDto(User user) {
            this.id = user.getId();
            this.username = user.getPassword();
            this.email = user.getEmail();
            this.role = user.getRole();
            this.CreatedAt = MyDateUtils.toStringFormat(user.getCreatedAt());
        }

    }
}
