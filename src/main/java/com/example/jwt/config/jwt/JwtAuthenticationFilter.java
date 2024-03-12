package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

//UsernamePasswordAuthenticationFilter: 시큐리티 필터 체인에 있는 필터
///login post 리퀘스트에 username과 password를 전송하면 해당 필터 동작 (formLogin을 disable 하면 동작하지 않음)
//해당 필터를 상속해 구현하고 시큐리티 필터 체인에 직접등록하면 formLogin이 disable인 상태에서도 필터 동작 가능

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    //formLogin을 사용한다면 /login 요청을 하면 로그인 시도를 위해 실행되는 로직
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter.attemptAuthentication");


        try {
            /*
            BufferedReader br = request.getReader();
            String input = null;
            while ((input=br.readLine())!=null){
                System.out.println(input);
            }
             */

            //1. username, password를 파싱
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);

            UsernamePasswordAuthenticationToken token
                    = new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());

            //manager가 가지고 있는 PrincipalDetailsService의 loadUserByUsername() 실행됨
            //loadUserByUsername은 token에서 username만 받아서 PrincipalDetails를 반환
            //manager는 PrincipalDetails의 password값(db값)과 token으로 전달된 password를 비교
            //정상적으로 인증되면 authentication는 PrincipalDetails가 담겨 return 됨
            Authentication authentication = authenticationManager.authenticate(token);

            //정상적인 principal 반환은 로그인 인증이 되었음을 의미
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();


            System.out.println(principalDetails.getUser().getUsername());
            //return 함으로서 authentication은 시큐리티 session에 저장됨
            //굳이 jwt 토큰을 사용하면서 세션을 만들 이유는 없음
            //하지만 return의 이유는 "권한 관리"를 security가 대신 해줘서 편리하기 때문
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }


    //attemptAuthentication 실행후 인증이 정상적으로 되었으면 실행되는 함수 
    //여기서 JWT 토큰을 만들어서 request 요청한 사용자에게 넘겨주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("JwtAuthenticationFilter.successfulAuthentication");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        //jwt 토큰 생성
        String jwtToken = JWT.create()
                .withSubject("cosToken")    //token subject 이름(큰 의미 없음)
                .withExpiresAt(new Date(System.currentTimeMillis() + 60000 * 30))   //만기 시간
                .withClaim("id", principalDetails.getUser().getId())    //포함하고 싶은 키 밸류값
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos")); //시크릿 키값과 시크니쳐 암호화 방식 설정

        //위 정보를 기반으로 JWT 토큰 스트링을 생성해줌


        //Bearer 방식임을 표시
        response.addHeader("Authorization", "Bearer "+jwtToken);
    }
}
