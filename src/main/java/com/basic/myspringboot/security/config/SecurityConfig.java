package com.basic.myspringboot.security.config;

import com.basic.myspringboot.security.jwt.JwtAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Spring Security 설정.
 *
 *   - 세션을 쓰지 않는 STATELESS + JWT 구조이므로 폼 로그인을 켜지 않는다.
 *     ( 폼 로그인을 켜두면 인증 실패 시 401 대신 /login 으로 302 리다이렉트된다 )
 *   - 인증 실패는 401, 권한 부족은 403 을 JSON 으로 응답한다.
 *   - UserDetailsService( @Service ) 와 PasswordEncoder 빈이 있으면
 *     Spring Boot 가 DaoAuthenticationProvider 를 자동으로 구성한다.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ObjectMapper objectMapper;
    private final MeterRegistry meterRegistry;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                //이 필터체인은 REST API(/api/**) 요청만 담당한다.
                //securityMatcher 로 범위를 한정하지 않으면 '모든 요청'에 매칭되어
                //뒤의 폼 로그인 체인이 실행되지 않는다.
                .securityMatcher("/api/**")
                //JWT 를 쓰는 REST API 이므로 CSRF 토큰이 필요 없다
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        //로그인과 회원가입은 토큰 없이 호출할 수 있어야 한다
                        .requestMatchers("/api/userinfos/welcome",
                                "/api/userinfos/new",
                                "/api/userinfos/login",
                                //[2단계] refresh·logout 은 access 토큰이 아니라 refresh 토큰으로 호출한다
                                "/api/userinfos/refresh",
                                "/api/userinfos/logout").permitAll()
                        //[교육용] SQL 인젝션 등 취약점 실습 엔드포인트는 인증 없이 접근 허용
                        //( 실무에서는 인증 뒤에 두지만, 인증이 인젝션을 막아 주지는 않는다 )
                        .requestMatchers("/api/vuln/**").permitAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().permitAll())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint())
                        .accessDeniedHandler(auditedAccessDeniedHandler()))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain formLoginFilterChain(HttpSecurity http)
            throws Exception {
        //securityMatcher 를 지정하지 않아 '모든 요청'을 담당하는 catch-all 체인이며,
        //@Order(2) 로 가장 마지막에 게시되어야 한다.(/api/** 는 위 JWT 체인이 먼저 처리)
        //[CSRF 하드닝] (OWASP #1) 세션+쿠키 기반이므로 CSRF 보호를 켠다(Spring Security 기본값).
        //  - Thymeleaf 폼(th:action)에는 _csrf 토큰이 자동 삽입되어 정상 동작
        //  - 공격자 페이지의 위조 요청은 토큰이 없어 403 으로 거부됨
        //  - JWT 체인은 Authorization 헤더 기반이라 위에서 csrf.disable() 을 유지한다
        return http
                //.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/login/**").permitAll()
                            .requestMatchers("/users/**").authenticated()
                            //[보안 설정 오류 하드닝] (OWASP #2) Actuator/Metrics 링크 모음 페이지.
                            //Actuator 자체의 ROLE_ADMIN 요구와는 별개로, 페이지 자체도 관리자만 보이게 막는다.
                            .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                            //[보안 설정 오류 하드닝] (OWASP #2) Actuator는 노출 범위(exposure.include)를
                            //최소화해도, 혹시 나중에 다시 넓어질 경우를 대비해 인증을 한 겹 더 요구한다.
                            //헬스체크는 로드밸런서 등 외부 도구가 인증 없이 호출해야 하므로 예외로 둔다.
                            .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                            .requestMatchers("/actuator/**").hasAuthority("ROLE_ADMIN")
                            //로그인 페이지·정적 리소스·루트 등 나머지는 접근 허용
                            .anyRequest().permitAll();
                })
                //.formLogin(withDefaults())
                .formLogin(login -> login
                        .loginPage("/login")
                        .loginProcessingUrl("/login-process")
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .defaultSuccessUrl("/users/index", true)
                        .permitAll()
                )
                .logout((logout) -> logout.logoutUrl("/app-logout")
                        .deleteCookies("JSESSIONID")
                        .logoutSuccessUrl("/")
                )
                //[CSP 하드닝] (OWASP XSS 방어) Thymeleaf 화면(이 체인)에만 적용한다.
                //  - script-src 'self' + cdn.jsdelivr.net : Bootstrap JS 는 CDN에서, 그 외 스크립트는 같은 출처에서만 허용
                //  - index-vuln.html 은 th:utext 로 사용자 입력을 그대로 렌더링하는 Stored XSS 데모 페이지이지만,
                //    CSP 가 있으면 주입된 <script> 가 응답 HTML에 그려져도 'self' 가 아니라서 브라우저가 실행을 차단한다
                //    (= 애플리케이션 코드의 결함과는 별개로 동작하는 심층 방어 계층)
                //  - inline onsubmit/style 은 모두 제거하고 외부 js/css 로 옮겼으므로 'unsafe-inline' 이 필요 없다
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives(
                                        "default-src 'self'; "
                                                + "script-src 'self' https://cdn.jsdelivr.net; "
                                                + "style-src 'self' https://cdn.jsdelivr.net; "
                                                + "img-src 'self'; "
                                                + "object-src 'none'; "
                                                + "base-uri 'self'; "
                                                + "frame-ancestors 'self'")))
                //[로깅 하드닝] 이 체인은 기존에 exceptionHandling 이 없어 401/403 이 Spring Security
                //기본 처리로 빠지며 [AUDIT] 로그가 전혀 남지 않았다. 401(미인증) 은 기존 로그인 페이지
                //리다이렉트 동작은 그대로 유지한 채 로그만 추가한다. 403(권한 부족)은 API 체인과 달리
                //JSON 이 아니라 templates/error/403.html(Thymeleaf 레이아웃 적용)을 보여준다.
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(auditedLoginEntryPoint())
                        .accessDeniedHandler(auditedHtmlAccessDeniedHandler()))
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * 토큰이 없거나 잘못된 경우 : 401
     * ( 이 처리는 DispatcherServlet 이전의 Security 필터 체인에서 끝나므로
     *   @RestControllerAdvice 의 AuthenticationException 핸들러는 호출되지 않는다.
     *   그래서 [AUDIT] 로그를 이 자리에서 직접 남긴다.
     *   auth.events 의 result=failure 와는 다르다 — 그것은 자격증명을 제출해
     *   AuthenticationManager.authenticate() 가 호출된 뒤 실패한 경우만 집계하므로,
     *   로그인 시도 자체가 없는 이 경로( 토큰 없음·만료 )에는 반응하지 않는다.
     *   그래서 별도 이름( unauthenticated.access.events, chain=api )으로 집계해
     *   access.denied.events(403) 와 짝을 맞춘다. )
     */
    private AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> {
            log.warn("[AUDIT] 인증 실패(401) - {} {} from {} : {}",
                    request.getMethod(), request.getRequestURI(), clientIp(request), authException.getMessage());
            meterRegistry.counter("unauthenticated.access.events", "chain", "api").increment();
            writeError(response, HttpServletResponse.SC_UNAUTHORIZED, "인증이 필요합니다 ( 유효한 토큰이 없습니다 )");
        };
    }

    /**
     * 폼 로그인 체인에서 미인증 상태로 보호된 경로에 접근한 경우.
     * ( 세션 기반이라 실제 응답은 401 이 아니라 /login 으로의 리다이렉트이지만,
     *   원인은 401 과 동일하게 "인증이 안 된 상태로 접근"이므로 같은 [AUDIT] 태그로 남긴다.
     *   응답 자체는 기존 LoginUrlAuthenticationEntryPoint 에 위임해 로그인 페이지로
     *   리다이렉트하는 동작을 그대로 유지한다.
     *   unauthenticated.access.events 카운터(chain=browser)로도 집계한다. )
     */
    private AuthenticationEntryPoint auditedLoginEntryPoint() {
        AuthenticationEntryPoint redirectToLogin = new LoginUrlAuthenticationEntryPoint("/login");
        return (request, response, authException) -> {
            log.warn("[AUDIT] 인증 실패(401) - {} {} from {} : {}",
                    request.getMethod(), request.getRequestURI(), clientIp(request), authException.getMessage());
            meterRegistry.counter("unauthenticated.access.events", "chain", "browser").increment();
            redirectToLogin.commence(request, response, authException);
        };
    }

    /**
     * 로그인은 했지만 권한이 부족한 경우 : 403 (REST API 체인 전용).
     * ( 401 과 같은 이유로 필터 체인 단계에서 끝나 @RestControllerAdvice 가 호출되지
     *   않으므로, [AUDIT] 로그를 이 자리에서 직접 남긴다. 브라우저용 응답은
     *   auditedHtmlAccessDeniedHandler() 를 따로 둔다 — API 는 JSON, 브라우저는 에러 페이지.
     *   access.denied.events 카운터(chain=api)로도 집계해 /actuator/metrics 로 조회할 수 있게 한다. )
     */
    private AccessDeniedHandler auditedAccessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            log.warn("[AUDIT] 접근 거부(403) - {} {} from {} : {}",
                    request.getMethod(), request.getRequestURI(), clientIp(request),
                    accessDeniedException.getMessage());
            meterRegistry.counter("access.denied.events", "chain", "api").increment();
            writeError(response, HttpServletResponse.SC_FORBIDDEN, "접근 권한이 없습니다");
        };
    }

    /**
     * 폼 로그인 체인(브라우저)에서 권한 부족으로 접근이 거부된 경우 : 403.
     * ( API 체인과 달리 JSON 이 아니라 templates/error/403.html 을 보여준다.
     *   response.sendError() 를 호출하면 서블릿 컨테이너가 /error 로 포워드하고,
     *   Spring Boot 의 BasicErrorController/DefaultErrorViewResolver 가 그 뷰를 찾아
     *   렌더링한다. templates 에 있으므로 Thymeleaf 레이아웃(헤더·네비바·푸터)이 그대로 적용된다.
     *   access.denied.events 카운터(chain=browser)로도 집계한다. )
     */
    private AccessDeniedHandler auditedHtmlAccessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            log.warn("[AUDIT] 접근 거부(403) - {} {} from {} : {}",
                    request.getMethod(), request.getRequestURI(), clientIp(request),
                    accessDeniedException.getMessage());
            meterRegistry.counter("access.denied.events", "chain", "browser").increment();
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "접근 권한이 없습니다");
        };
    }

    /**
     * 클라이언트 IP 추출. 프록시 뒤라면 X-Forwarded-For 의 첫 IP 를 사용한다.
     * ( 감사 로그에 출처를 남기기 위한 용도 )
     */
    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private void writeError(HttpServletResponse response, int status, String message)
            throws java.io.IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getWriter(), Map.of(
                "statusCode", status,
                "message", message,
                "timestamp", LocalDateTime.now().toString()));
    }
}
