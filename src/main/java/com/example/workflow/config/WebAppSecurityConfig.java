package com.example.workflow.config;

import com.example.workflow.filter.webapp.WebAppAuthenticationProvider;
import jakarta.inject.Inject;
import org.camunda.bpm.spring.boot.starter.property.CamundaBpmProperties;
import org.camunda.bpm.webapp.impl.security.auth.ContainerBasedAuthenticationFilter;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@Configuration
public class WebAppSecurityConfig {

    @Autowired
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
    @Inject
    private CamundaBpmProperties camundaBpmProperties;

    // change : Return a Spring Bean SecurityFilterChain
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // Create a filter to handle generation of SAML Metadata file
        Saml2MetadataFilter filter = new Saml2MetadataFilter(
                new DefaultRelyingPartyRegistrationResolver(this.relyingPartyRegistrationRepository),
                new OpenSamlMetadataResolver());

        // Actual code to extract the Authorities (or roles) from the Assertion
        Converter<Assertion, Collection<? extends GrantedAuthority>> authoritiesExtractor = assertion -> {

            List<SimpleGrantedAuthority> userRoles
                    = assertion.getAttributeStatements()
                    .stream()
                    .map(AttributeStatement::getAttributes)
                    .flatMap(Collection::stream)
                    .filter(attr -> "groups".equalsIgnoreCase(attr.getName()))
                    .map(Attribute::getAttributeValues)
                    .flatMap(Collection::stream)
                    .map(xml -> new SimpleGrantedAuthority("ROLE_" + xml.getDOM()
                            .getTextContent()))
                    .toList();
            return userRoles;
        };

        // change : Create a version of SAML Authenticator Provider which will convert the
        // "groups" claim into Authorities in the SAML 2 Authentication object
        Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> authConvertor
                = OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();
        OpenSaml4AuthenticationProvider samlAuthProv = new OpenSaml4AuthenticationProvider();
        samlAuthProv.setResponseAuthenticationConverter((responseToken) -> {

            // Make sure the authorities are set in the SAML Authentication
            Saml2Authentication authentication = authConvertor.convert(responseToken);
            Assertion assertion = responseToken.getResponse()
                    .getAssertions()
                    .get(0);
            AuthenticatedPrincipal principal = (AuthenticatedPrincipal) authentication.getPrincipal();
            Collection<? extends GrantedAuthority> authorities = authoritiesExtractor.convert(assertion);
            return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
        });

        String webAppPath = camundaBpmProperties.getWebapp()
                .getApplicationPath(); //default value for root-context is /camunda

        http.csrf(csrf -> csrf.disable())
                .saml2Login(withDefaults())
//                .saml2Logout(withDefaults())
                .authenticationProvider(samlAuthProv) // change : register the new SAML Auth provider
                .addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class)
                .authorizeHttpRequests(authorize ->
                                               authorize
                                                       .requestMatchers(antMatcher("/swaggerui/**"))
                                                       .permitAll()
                                                       .requestMatchers(antMatcher("/logout"))
                                                       .permitAll()
                                                       .requestMatchers(antMatcher(webAppPath + "/**"))
                                                       .authenticated()
                                                       .anyRequest()
                                                       .permitAll());

        // change : return the SecurityFilterChain
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
