package com.example.exceptiondemo.model;

import com.example.exceptiondemo.enums.TokenType;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Date;

@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "tokens")
@FieldDefaults(level = AccessLevel.PRIVATE)
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Integer id;

    String token;

    @Enumerated(EnumType.STRING)
    TokenType tokenType;

    Date expireToken;

    boolean expired;

    boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id")
    User user;

    String refreshToken;

    Date refreshExpirationDate;
}
