package com.example.jwt.config;

import com.example.jwt.config.auth.PrincipalDetailService;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.config.jwt.JwtAuthorizationFilter;
import com.example.jwt.filter.MyFilter1;
import com.example.jwt.config.jwt.JwtAuthenticationFilter;
import com.example.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity  //스프링 시큐리티 필터가 스프링 필터체인에 등록됨 (시큐리티가 기본 제공하는 필터를 재정의, 덮어씌움)
//@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)    //secured, pre/postAuthorize 어노테이션 활성화
@RequiredArgsConstructor
public class SecurityConfig{

    private final PrincipalDetailService principalDetailService;
    private final UserRepository userRepository;
    private final CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        AuthenticationManagerBuilder sharedObject = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = sharedObject.build();
        http.authenticationManager(authenticationManager);

        //http.addFilterBefore(new MyFilter1(), UsernamePasswordAuthenticationFilter.class);  //securityFilterChain 앞쪽 chain에 필터 등록

        return http.csrf(cs->cs.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //세션을 사용하지 않는 설정
                .addFilter(corsFilter)  //시큐리티 필터 체인에 또다른 필터 등록
                .addFilterAt(new JwtAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)  //AuthenticationManager를 파라미터로 줘야함(login을 진행하는 컴포넌트)
                .addFilterAt(new JwtAuthorizationFilter(authenticationManager, userRepository), BasicAuthenticationFilter.class)
                .formLogin(fl -> fl.disable())  //formLogin을 사용하지 않음
                .httpBasic(hb -> hb.disable())  //Basic 방식의 인증을 사용하지 않음
                .authorizeHttpRequests(ahr->ahr.requestMatchers("/api/v1/user/**").hasAnyRole("USER","MANAGER", "ADMIN")
                        .requestMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN")
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .anyRequest().permitAll()).build();
    }

    //security 필터 체인에 등록할 필터들을 설정한 후 한번에 등록 가능하게 해주는 객체
    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {

            AuthenticationManagerBuilder sharedObject = http.getSharedObject(AuthenticationManagerBuilder.class);
            sharedObject.userDetailsService(principalDetailService);
            AuthenticationManager authenticationManager = sharedObject.build();
            http.authenticationManager(authenticationManager);

            http.addFilter(corsFilter)
                    .addFilter(new JwtAuthenticationFilter(authenticationManager));
                    //.addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
        }
    }
}
