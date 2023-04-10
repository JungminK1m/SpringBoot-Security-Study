package shop.mtcoding.securityapp.model;

import java.time.LocalDateTime;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor // Hibernate가 ORM시에 new 하려고 필요함
@Getter // setter는 만들 필요 없음
@Table(name = "user_tb")
@Entity // Hibernate가 관리(영속, 비영속, 준영속)
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // auto increment 전략
    private Long id;
    private String username;
    private String password;
    private String email;
    private String role; // USER, MANAGER, ADMIN
    private Boolean status; // true, false

    // @CreationTimestamp timestamp가 아니므로 안먹힘
    private LocalDateTime createdAt;
    private LocalDateTime updateAt;

    @PrePersist // insert시에 동작
    public void onCreate() {
        this.createdAt = LocalDateTime.now();
    }

    @PreUpdate // update시에 동작
    public void onUptate() {
        this.updateAt = LocalDateTime.now();
    }

    // constructor 생성
    @Builder
    public User(Long id, String username, String password, String email, String role, Boolean status,
            LocalDateTime createdAt, LocalDateTime updateAt) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
        this.status = status;
        this.createdAt = createdAt;
        this.updateAt = updateAt;
    }

}
