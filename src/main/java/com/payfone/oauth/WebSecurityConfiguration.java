package com.payfone.oauth;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter
{
    private static final String TOKEN_URI = "/oauth/token";
    private static final String SIGNING_KEY = "1234567890123456780tlsabacadaba";

    // @Autowired
    // private UserDetailsService userDetailsService;

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception
    {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception
    {
        //auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());

        auth.inMemoryAuthentication().withUser("bofa_user").password(passwordEncoder().encode("bofa_user_pw")).roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .csrf().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, TOKEN_URI).permitAll()
                .anyRequest().authenticated();
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter()
    {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(SIGNING_KEY);
        converter.setAccessTokenConverter(accessTokenConverter());
        return converter;
    }

    @Bean
    public DefaultAccessTokenConverter accessTokenConverter()
    {
        return new DefaultAccessTokenConverter()
        {
            @Override
            public OAuth2Authentication extractAuthentication(Map<String, ?> claims)
            {
                OAuth2Authentication authentication = super.extractAuthentication(claims);
                authentication.setDetails(claims);
                return authentication;
            }
        };
    }

    @Bean
    public TokenStore jwtTokenStore()
    {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    // Required bean
    @Bean
    @Primary
    public DefaultTokenServices tokenServices()
    {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(jwtTokenStore());
        defaultTokenServices.setTokenEnhancer(tokenEnhancer());
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public TokenEnhancer tokenEnhancer()
    {
        return new TokenEnhancer()
        {
            // Provides an opportunity for customization of an access token
            // during the process of creating a new token for use by a client.

            // The "sub_client_id" parameter key gets translated to "username"
            // In AuthorizationServerConfiguration.PayfoneOAuth2RequestFactory.createTokenRequest()
            private static final String SUB_CLIENT_ID = "sub_client_id";
            private static final String SUB_CLIENT = "username";
            private static final String CLIENT = "client_id";
            private static final String SUB_CLIENT_ALIAS = "sub_client_alias";

            @Override
            public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication)
            {
                // Input credentials/parameters
                OAuth2Request oAuth2Request = authentication.getOAuth2Request();
                Map<String, String> requestParameters = oAuth2Request.getRequestParameters();

                // LinkedHashMap keeps the order of the additional info fields
                Map<String, Object> additionalInfo = new LinkedHashMap<String, Object>();
                additionalInfo.put(CLIENT, oAuth2Request.getClientId());
                additionalInfo.put(SUB_CLIENT_ID, requestParameters.get(SUB_CLIENT));
                additionalInfo.put(SUB_CLIENT_ALIAS, requestParameters.get(SUB_CLIENT_ALIAS));
                ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
                return accessToken;
            }
        };
    }
}
