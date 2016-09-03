/**
 * This is a configuration class
 * 
 */

package com.jorge.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;


@Configuration // This declares it as a Spring configuration class
@EnableWebMvc // This enables Spring's ability to receive and process web requests. Necessary for interceptors too.
@ComponentScan(basePackages = { "com.jorge.controller" }) // This scans the com.jorge.controller package for Spring components

// @Import({ DatabaseConfig.class, SecurityConfig.class }) => //If you are using a Spring application without a 'ServletInitializer' class,
														      // you can include other configuration classes from your primary configuration class

public class AppConfig {

	 @Bean 
	 public ViewResolver jspViewResolver(){ 
		 InternalResourceViewResolver resolver = new InternalResourceViewResolver();
		 
	 	 resolver.setViewClass(JstlView.class);
	 	 resolver.setPrefix("/WEB-INF/jsp/"); // These folders must be created on /src/main/webapp/ 
	 	 resolver.setSuffix(".jsp"); 
	 	 
	 	 return resolver; 
	 }
	
}