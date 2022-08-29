package com.example.workflow.config;

import com.example.workflow.filter.webapp.WebAppAuthenticationProvider;
import org.camunda.bpm.webapp.impl.security.auth.ContainerBasedAuthenticationFilter;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Configuration
public class WebAppSecurityConfig {

    private final CustomLogoutSuccessHandler customLogoutSuccessHandler;
    GrantedAuthoritiesMapper authoritiesMapper = (authCol -> authCol);
    // Actual code to extract the Authorities (or roles) from the Assertion
    Converter<Assertion, Collection<? extends GrantedAuthority>> authoritiesExtractor = assertion -> {

        List<SimpleGrantedAuthority> userRoles
                = assertion.getAttributeStatements().stream()
                .map(AttributeStatement::getAttributes)
                .flatMap(Collection::stream)
                .filter(attr -> "groups".equalsIgnoreCase(attr.getName()))
                .map(Attribute::getAttributeValues)
                .flatMap(Collection::stream)
                .map(xml -> new SimpleGrantedAuthority("ROLE_" + xml.getDOM().getTextContent()))
                .toList();
        return userRoles;
    };
    @Value("${sso.enable.singlelogout}")
    private boolean singleLogout;
    public WebAppSecurityConfig(CustomLogoutSuccessHandler customLogoutSuccessHandler) {
        this.customLogoutSuccessHandler = customLogoutSuccessHandler;
    }

    @SuppressWarnings("deprecation") //OpenSaml4 jars are not available by default in Spring security
    @Bean
    public SecurityFilterChain webAppFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().ignoringAntMatchers("/engine-rest/**", "/camunda/api/**")
                .and()
                .authorizeRequests()
                .antMatchers("/swaggerui/**", "/engine-rest/**", "/error/**")
                .permitAll()
                .and()
                .antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/camunda/**")
                .authenticated()
                .anyRequest()
                .permitAll()
                .and()
                .saml2Login()
                .addObjectPostProcessor(new ObjectPostProcessor<OpenSamlAuthenticationProvider>() {
                    public <P extends OpenSamlAuthenticationProvider> P postProcess(
                            P samlAuthProvider) {

                        // Set the Authorities extractor
                        samlAuthProvider.setAuthoritiesExtractor(authoritiesExtractor);
                        samlAuthProvider.setAuthoritiesMapper(authoritiesMapper);
                        return samlAuthProvider;
                    }
                });

        if (singleLogout) {
            http
                    .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/**/logout"))
                    .logoutSuccessHandler(customLogoutSuccessHandler);

        }
        return http.build();
    }

    @Bean
    public FilterRegistrationBean containerBasedAuthenticationFilter() {

        FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
        filterRegistration.setFilter(new ContainerBasedAuthenticationFilter());
        filterRegistration.setInitParameters(Collections.singletonMap("authentication-provider", WebAppAuthenticationProvider.class.getName()));
        filterRegistration.setOrder(101); // make sure the filter is registered after the Spring Security Filter Chain
        filterRegistration.addUrlPatterns("/camunda/app/*");
        return filterRegistration;
    }

}
