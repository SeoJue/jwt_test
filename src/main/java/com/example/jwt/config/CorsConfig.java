package com.example.jwt.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;


@Configuration
public class CorsConfig {

    //CORS 요청에 대한 허가를 가능하게 해주는 필터
    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);   //쿠키와 같은 Credential을 포함한 리퀘스트를 허용하는 설정
        config.addAllowedOrigin("*");   //모든 origin에 대해 응답 허용
        config.addAllowedHeader("*");   //모든 header에 대해 응답 허용
        config.addAllowedMethod("*");   //모든 http method에 대해 응답 허용
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }
}
