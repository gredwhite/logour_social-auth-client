/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;

/**
 * Test client for use with social application (as an OAuth2 auth server). Remember to
 * access this app via its IP address (not "localhost"), otherwise the auth server will
 * steal your cookie.
 *
 * @author Dave Syer
 */
@EnableAutoConfiguration
@Configuration
@EnableOAuth2Sso
@Controller
public class ClientApplication extends WebSecurityConfigurerAdapter {
    private Logger logger = LoggerFactory.getLogger(ClientApplication.class);

    @RequestMapping("/hello")
    public String home(Principal user, HttpServletRequest request, HttpServletResponse response, Model model) throws ServletException {
        model.addAttribute("name", user.getName());
        return "hello";
    }

    /*@Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.antMatcher("/**")
                .authorizeRequests()
                .antMatchers( "/login**", "/webjars/**", "/error**").permitAll()
                .anyRequest()
                .authenticated()
                .and().logout().logoutSuccessUrl("/").permitAll()
                .and()
                    .csrf()
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        // @formatter:on
    }*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.antMatcher("/**")
                .authorizeRequests()
                .antMatchers( "/login**", "/webjars/**", "/error**").permitAll()
                .anyRequest()
                .authenticated()
                .and().logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/client/logout"))
                .logoutSuccessUrl("/").permitAll()
                .and()
                .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        // @formatter:on
    }

    public static void main(String[] args) {
        new SpringApplicationBuilder(ClientApplication.class)
                .properties("spring.config.name=application").run(args);
    }
}
