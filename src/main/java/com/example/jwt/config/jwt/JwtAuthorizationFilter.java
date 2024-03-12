package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;


//시큐리티 filter chain에서 BasicAuthenticationFilter 역할로서 구현
//BasicAuthenticationFilter: 권한이나 인증이 필요한 특정 주소를 요청했을 때 처리 로직을 가지는 필터 (인증 필요 주소가 아니라면 동작 X)
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    //인증이나 권한이 필요한 주소요청이 있을 떄 해당 로직이 실행됨
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        System.out.println("JwtAuthorizationFilter.JwtAuthorizationFilter");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwt Header: " + jwtHeader);


        //JWT 토큰 검증
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request, response);
        }

        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");

        //토큰값이 정상적(정상적을 서명됨)이라면 페이로드의 값을 가지고 올 수 있음
        String username = JWT.require(Algorithm.HMAC512("cos")).build()
                .verify(jwtToken).getClaim("username").asString();

        //서명이 정상적으로 된 경우
        if(username != null){
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            //jwt 토큰 서명을 통해 만든 객체 (jwtAuthenticationFilter에서 로그인을 통해 만든 방식과는 다름)
            //서명이 정상적으로 됐으므로 사용자라는 근거가 있어 만들 수 있음
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());


            //SecurityContextHolder.getContext(): 시큐리티 세션 공간을 반환
            //시큐리티 세션에 authentication이 들어있음은 유저가 인증이 되었음을 의미
            //또한 시큐리티 세션 authentication이 들어가야 시큐리티가 인식하여 로직에 사용하며 컨트롤러단에서도 참조할 수 있음 (저장소 역할)
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }
    }
}
