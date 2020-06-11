package com.jmworks.auth.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

//@Configuration
//@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

//    @Override
//    public void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests().anyRequest().authenticated()
//                .and()
//                .requestMatchers().antMatchers("/api/**");
//    }

//    public TokenStore tokenStore() {
//        return new JwtTokenStore(accessTokenConverter());
//    }
//
//    public JwtAccessTokenConverter accessTokenConverter() {
//        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
//        Resource resource = new ClassPathResource("kr.ejsoft.oauth2.publickey.txt");
//        String publickey = null;
//        try {
//            publickey = asString(resource);
//        } catch(final IOException e) {
//            throw new RuntimeException(e);
//        }
//
//        converter.setVerifierKey(publickey);
//        return converter;
//    }
//
//    public static String asString(Resource resource) throws IOException {
//        Reader reader = new InputStreamReader(resource.getInputStream(), "UTF-8");
//        return FileCopyUtils.copyToString(reader);
//    }

}
