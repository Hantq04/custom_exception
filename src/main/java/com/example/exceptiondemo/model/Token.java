package com.example.exceptiondemo.model;

import com.example.exceptiondemo.enums.TokenType;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

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

    boolean expired;

    boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id")
    User user;
}
