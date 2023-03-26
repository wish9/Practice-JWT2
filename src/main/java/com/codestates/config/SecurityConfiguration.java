package com.codestates.config;

import com.codestates.auth.JwtTokenizer;
import com.codestates.auth.filter.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfiguration {
    private final JwtTokenizer jwtTokenizer;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer) {
        this.jwtTokenizer = jwtTokenizer;
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .headers().frameOptions().sameOrigin() // 동일 출처로부터 들어오는 request만 페이지 렌더링을 허용 (H2 웹 콘솔(개발단계용으로) 쓰기 위해 추가한거)
                .and()
                .csrf().disable()        // CSRF공격에 대한 Spring Security에 대한 설정을 비활성화
                .cors(withDefaults())    // CORS 설정 추가 (corsConfigurationSource라는 이름으로 등록된 Bean을 이용)
                .formLogin().disable()   // 폼 로그인 방식을 비활성화
                .httpBasic().disable()   // HTTP Basic 인증 방식을 비활성화
                .apply(new CustomFilterConfigurer())   // Custom Configurer 적용
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll()                // 모든 HTTP request 요청에 대해서 접근 허용
                );
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder(); // PasswordEncoder Bean 객체 생성
    }

    // CORS 정책 설정하는 방법
    @Bean
    CorsConfigurationSource corsConfigurationSource() { // CorsConfigurationSource Bean 생성을 통해 구체적인 CORS 정책을 설정
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));   // 모든 출처(Origin)에 대해 스크립트 기반의 HTTP 통신을 허용하도록 설정
        configuration.setAllowedMethods(Arrays.asList("GET","POST", "PATCH", "DELETE"));  // 파라미터로 지정한 HTTP Method에 대한 HTTP 통신을 허용

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();   // CorsConfigurationSource 인터페이스의 구현 클래스인 UrlBasedCorsConfigurationSource 클래스의 객체를 생성
        source.registerCorsConfiguration("/**", configuration);      // 모든 URL에 앞에서 구성한 CORS 정책(CorsConfiguration)을 적용
        return source;
    }

    // Custom Configurer 클래스 (JwtAuthenticationFilter를 등록하는 역할)
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity> {  // AbstractHttpConfigurer를 상속해서 Custom Configurer를 구현할 수 있다.
        @Override
        public void configure(HttpSecurity builder) throws Exception {  // configure() 메서드를 오버라이드해서 Configuration을 커스터마이징
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);  // AuthenticationManager 객체 가져오기

            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);  // JwtAuthenticationFilter를 생성하면서 JwtAuthenticationFilter에서 사용되는 AuthenticationManager와 JwtTokenizer를 DI
            jwtAuthenticationFilter.setFilterProcessesUrl("/v11/auth/login");          // setFilterProcessesUrl() 메서드를 통해 디폴트 request URL인 “/login”을 “/v11/auth/login”으로 변경

            builder.addFilter(jwtAuthenticationFilter);  // addFilter() 메서드를 통해 JwtAuthenticationFilter를 Spring Security Filter Chain에 추가
        }
    }
}