package cn.com.onedream.jwtdemo.auth.config;

import cn.com.onedream.jwtdemo.auth.filter.JwtFilter;
import cn.com.onedream.jwtdemo.auth.filter.JwtLoginFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private PasswordEncoder passwordEncoder;

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    //使用BCryptPasswordEncoder进行密码加密
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/hello").hasRole("user")
                .antMatchers("/admin").hasRole("admin")
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                .anyRequest().authenticated()
                .and()
                //从WebSecurityConfigurerAdapter中获取AuthenticationManager对象（WebSecurityConfigurerAdapter.authenticationManager()）
                .addFilterBefore(new JwtLoginFilter("/login",authenticationManager())
                        ,UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtFilter(), UsernamePasswordAuthenticationFilter.class)
                .csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //创建内存用户，后去替换成数据库存储
        auth.inMemoryAuthentication().withUser("admin")
                .password(passwordEncoder.encode("123456")).roles("admin")
                .and()
                .withUser("test")
                .password(passwordEncoder.encode("123456"))
                .roles("user");
    }
}
