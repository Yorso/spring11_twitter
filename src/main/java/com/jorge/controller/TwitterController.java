package com.jorge.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.social.connect.Connection;
import org.springframework.social.oauth1.AuthorizedRequestToken;
import org.springframework.social.oauth1.OAuth1Operations;
import org.springframework.social.oauth1.OAuth1Parameters;
import org.springframework.social.oauth1.OAuthToken;
import org.springframework.social.twitter.api.Twitter;
import org.springframework.social.twitter.api.TwitterProfile;
import org.springframework.social.twitter.connect.TwitterConnectionFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller
public class TwitterController {

	// Data given by Twitter when we create the app
	private String consumerKey = "ERmbXPyVhZHGhyGRuPhh920Gk";
	private String consumerSecret = "ZdEIeIw2nfWFMlFYNjOGOY4Qdz89Aurz8e6BeBWrGEFxfgmrCJ";
	private static boolean user = false; // Used for redirections
	
	
	/*************************************************************************************
	 * Twitter configuration:
	 * 		Go to https://apps.twitter.com and create new app
	 * 		Name: My Spring-Twitter App
	 *  	Description: Spring-Twitter integration app
	 * 		Website: http://192.168.1.42:8080/spring11_twitter/tw
	 * 		Callback: http://192.168.1.42:8080/spring11_twitter/tw/callback
	 * 		Check "Allow this application to be used to Sign in with Twitter"
	 * 
	 * 192.168.1.42 is the local IP of our computer. Not allowed, i.e,  http://localhost:8080/spring11_twitter/tw
	 * 
	 * Try: http://192.168.1.42:8080/spring11_twitter/tw
	 *
	 *
	 *	The login() method builds a Twitter authorization URL using the API key and redirects the user to it
	 * Once the user has authorized our Twitter application, he/she is redirected back to our web
	 * application to a callback URL, /tw/callback , that we provided with this line:
	 * 		OAuthToken requestToken = oauthOperations.fetchRequestToken("http://192.168.1.42:8080/spring11_twitter/tw/callback", null);
	 * 
	 * The callback URL contains a oauth_verifier parameter provided by Twitter.
	 * In the callback() method, we use this authorization code to get an OAuth access token that we store
	 * in the session. This is part of the standard OAuth workflow; the token is not provided directly, so it's
	 * not shown to the user. On our server, the application secret (also never shown to the user) is required
	 * to obtain the token from the authorization code.
	 * 
	 * We then redirect the user to /tw. In the tw() method, we retrieve the token from the session and use it
	 * to connect to the user's Twitter account
	 *
	 */
	// Create a Twitter login method containing your API key and API secret, which will redirect to	Twitter's authorization page
	@RequestMapping("/tw/login")
	public void login(HttpServletRequest request, HttpServletResponse response, HttpSession session)	throws IOException {
		TwitterConnectionFactory connectionFactory = new TwitterConnectionFactory(consumerKey, consumerSecret); // (Consumer Key, Consumer Secret)

		try{
			OAuth1Operations oauthOperations =	connectionFactory.getOAuthOperations();
			
			OAuthToken requestToken = oauthOperations.fetchRequestToken("http://192.168.1.42:8080/spring11_twitter/tw/callback", null);
			
			session.setAttribute("requestToken", requestToken);
			
			String authorizeUrl = oauthOperations.buildAuthenticateUrl(requestToken.getValue(),	OAuth1Parameters.NONE);
			
			response.sendRedirect(authorizeUrl);
			
		}
		catch(Exception e){
			//response.sendRedirect("../error"); // Error page, key and/or secret values are wrong. Goes to 'public String errorPage()' method below
											   	 // We write ../error because its current path in browser is http://192.168.1.42:8080/spring11_twitter/tw/error but error page true path is in http://192.168.1.42:8080/spring11_twitter/error
											     // We can write @RequestMapping("/tw/error") and write response.sendRedirect("error"); Final path in browser would be http://192.168.1.42:8080/spring11_twitter/tw/error but in project WEB-INF/jsp/error
			response.sendRedirect("error");
		}
	}
	
	// Error page
	//@RequestMapping("/error")
	@RequestMapping("/tw/error")
	public String errorPage() {
		return "error";
	}
	
	// Create the callback method, where the user will be redirected after logging in to Twitter.
	// Use the oauth_verifier parameter received from Twitter as well as the request token from
	// login() to get an access token and save it in the session
	@RequestMapping("/tw/callback")
	public String callback(String oauth_token, String oauth_verifier, HttpServletRequest request, HttpSession session) {
		TwitterConnectionFactory connectionFactory = new TwitterConnectionFactory(consumerKey, consumerSecret); // (Consumer Key, Consumer Secret)

		OAuthToken requestToken = (OAuthToken) session.getAttribute("requestToken");
		
		if(requestToken != null){
			OAuth1Operations oAuthOperations = connectionFactory.getOAuthOperations();
		
			try{
				OAuthToken token = oAuthOperations.exchangeForAccessToken(new AuthorizedRequestToken(requestToken, oauth_verifier), null);
				session.setAttribute("twitterToken", token);
			}
			catch (Exception e) {
				return "redirect:/tw";
			}
		
		}
		
		return "redirect:/tw";
	}
	
	// Create a method that will display a JSP if it manages to connect to Twitter. Otherwise, it will redirect to the login URL
	@RequestMapping("/tw")
	public String tw(HttpServletRequest request, HttpSession session) {
		OAuthToken token = (OAuthToken)	session.getAttribute("twitterToken");
		
		if(token == null) {
			return "redirect:/tw/login";
		}
		
		TwitterConnectionFactory connectionFactory = new TwitterConnectionFactory(consumerKey, consumerSecret); // (Consumer Key, Consumer Secret)
		
		try{
			Connection<Twitter> connection = connectionFactory.createConnection(token);
			
			Twitter twitter = connection.getApi();
			
			if( ! twitter.isAuthorized()) {
				return "/tw/login";
			}
		}
		catch(Exception e){
			return "error";
		}
		
			
		return user?"redirect:/fw":"tw";
	}
	
	
	
	/***************************************************************************************
	 * Retrieving a user's Twitter profile
	 * 
	 * We'll learn how to retrieve a user's Twitter profile data, which automatically becomes
	 * available to the Twitter application once the user has authorized the Twitter application.
	 * 
	 */
	@RequestMapping("/fw")
	public String fb(HttpServletRequest request, Model model, HttpSession session) {
		user = user?false:true;
		
		OAuthToken token = (OAuthToken)	session.getAttribute("twitterToken");
		TwitterConnectionFactory connectionFactory = new TwitterConnectionFactory(consumerKey, consumerSecret); // (Consumer Key, Consumer Secret)
		try{
			Connection<Twitter> connection = connectionFactory.createConnection(token);
			Twitter twitter = connection.getApi();
			
			if( ! twitter.isAuthorized()) {
				return "redirect:/tw/login";
			}
			else{
				TwitterProfile profile = twitter.userOperations().getUserProfile(); // Twitter object to retrieve the user profile
				model.addAttribute("profile", profile); // Pass the user profile to the JSP view
				user = false;
				
				return "user";
			}
		}
		catch(Exception e){
			return "redirect:/tw/login";
		}
	}
	
}
