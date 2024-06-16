package com.example.workflow.config;

import org.camunda.bpm.engine.identity.Group;
import org.camunda.bpm.engine.identity.User;
import org.camunda.bpm.engine.impl.cfg.ProcessEngineConfigurationImpl;
import org.camunda.bpm.engine.impl.identity.WritableIdentityProvider;
import org.camunda.bpm.engine.impl.identity.db.DbGroupQueryImpl;
import org.camunda.bpm.engine.impl.identity.db.DbIdentityServiceProvider;
import org.camunda.bpm.engine.impl.identity.db.DbUserQueryImpl;
import org.camunda.bpm.engine.impl.interceptor.Session;
import org.camunda.bpm.engine.impl.interceptor.SessionFactory;
import org.camunda.bpm.engine.impl.persistence.entity.UserEntity;
import org.camunda.bpm.engine.spring.SpringProcessEnginePlugin;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
public class IdentityProviderPlugin extends SpringProcessEnginePlugin {
    /*
     * IdentityProviderPlugin is required since Camunda 7.19. Camunda implemented a security feature to cache the auth info
     * for finite time only. Refer below links for more info
     * https://docs.camunda.org/security/notices/#notice-85
     * https://docs.camunda.org/manual/7.19/user-guide/security/#authentication-cache
     * https://github.com/camunda-consulting/camunda-7-code-examples/tree/main/snippets/springboot-security-sso
     * https://github.com/camunda/camunda-bpm-platform/issues/3475
     * https://github.com/camunda/camunda-bpm-platform/issues/3689
     * In this implementation, I am querying groups and users against DB first and then SecurityContextHolder
     * */

    public void preInit(ProcessEngineConfigurationImpl processEngineConfiguration) {
        processEngineConfiguration.setIdentityProviderSessionFactory(new SessionFactory() {
            @Override
            public Class<?> getSessionType() {
                return WritableIdentityProvider.class;
            }

            @Override
            public Session openSession() {
                return new DbIdentityServiceProvider() {
                    //Here I am fetching Groups from Camunda Database First and then in Spring security context. You can change the logic based on your need.
                    @Override
                    public List<Group> findGroupByQueryCriteria(DbGroupQueryImpl query) {
                        List<Group> groups = super.findGroupByQueryCriteria(query);
                        if (!groups.isEmpty()) {
                            return groups;
                        }
//                        You can delete this logic if you donot want to use OKTA groups and use groups form DB only
                        String userId = query.getUserId();
                        if (userId != null) {
                            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                            if (authentication != null ) {
                                List<String> groupIds = authentication.getAuthorities()
                                        .stream()
                                        .map(GrantedAuthority::getAuthority)
                                        .map(res -> res.substring(5)) // Strip "ROLE_"
                                        .collect(Collectors.toList());

                                if (!groupIds.isEmpty()) {
                                    return groupIds.stream()
                                            .map(groupId -> {
                                                Group group = createNewGroup(groupId);
                                                group.setName(groupId);
                                                return group;
                                            })
                                            .collect(Collectors.toList());
                                }
                            }
                        }

                        return Collections.emptyList();
                    }

                    //                    Searching User in Database first and then in Spring security. You can tweak the sequence of lookup based on need .
//                    or you can keep the lookup you need.
                    @Override
                    public List<User> findUserByQueryCriteria(DbUserQueryImpl query) {
                        List<User> users = super.findUserByQueryCriteria(query);
                        if (!users.isEmpty()) {
                            return users;
                        }

                        String userId = query.getId();
                        if (userId != null) {
                            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                            if (authentication != null && authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal samlUser) {
                                UserEntity userEntity = new UserEntity();
                                userEntity.setId(samlUser.getName());
                                userEntity.setFirstName(samlUser.getFirstAttribute("first"));
                                userEntity.setLastName(samlUser.getFirstAttribute("last"));
                                userEntity.setEmail(samlUser.getFirstAttribute("email"));
                                return Collections.singletonList(userEntity);
                            }
                        }

                        return Collections.emptyList();
                    }
                };
            }
        });
    }

}