package spring_security_jwt.security;



import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    // Definindo o PasswordEncoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //liberando essas rotas específicas para que sejam acessíveis sem autenticação
    private static final String[] SWAGGER_WHITELIST = {
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/webjars/**",
            "/v3/api-docs/**", // Rotas do Swagger 3
            "/swagger-ui/**"   // Nova rota do Swagger UI
    };
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Desabilitando frameOptions para permitir o uso do H2
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.disable()))
                // Configurações de CORS e CSRF
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                // Adicionando o filtro JWT após o filtro de autenticação de senha
                .addFilterAfter(new JWTFilter(), UsernamePasswordAuthenticationFilter.class)
                // Configurando permissões
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers(SWAGGER_WHITELIST).permitAll()  // Liberando Swagger
                        .requestMatchers("/h2-console/**").permitAll()    // Liberando o H2 console
                        .requestMatchers(HttpMethod.POST, "/login").permitAll()  // Liberando login
                        .requestMatchers(HttpMethod.POST, "/users").permitAll()  // Liberando cadastro de usuários
                        .requestMatchers(HttpMethod.GET, "/users").hasAnyRole("USERS", "MANAGERS")  // Requer permissão para visualizar usuários
                        .requestMatchers("/managers").hasAnyRole("MANAGERS")  // Requer permissão para gerentes
                        .anyRequest().authenticated()  // Qualquer outra requisição requer autenticação
                )
                // Configuração de sessão para ser STATELESS, necessário para JWT
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return http.build();
    }

    //Abordagem moderna utilizando o console H2 via application.properties
    //Evita problemas de compatibilidade entre diferentes versões de dependências
    /*
    @Bean
    public ServletRegistrationBean<WebServlet> h2servletRegistration(){
        ServletRegistrationBean<WebServlet> registrationBean =
                new ServletRegistrationBean<>(new WebServlet(), "/h2-console/*");
        return registrationBean;
    }
        */
}
