<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page isELIgnored="false" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<title>Tweeter User Info</title>
	</head>
	<body>
		<h3>User Info:</h3>
		name: ${profile.name}<br />
		screenName: ${profile.screenName}<br />
		url: ${profile.url}<br />
		profileImageUrl: ${profile.profileImageUrl}<br />
		description: ${profile.description}<br />
		location: ${profile.location}<br />
		createdDate: ${profile.createdDate}<br />
		language: ${profile.language}<br />
		statusesCount: ${profile.statusesCount}<br />
		followersCount: ${profile.followersCount}
		
		<hr/>
		
		<h3>Tweets:</h3>
		<c:forEach items="${tweets}" var="tweet">
			<p>${tweet.text}</p>
		</c:forEach>
		
	</body>
</html>