package org.jivesoftware.openfire;

/**
*@author Yrjan Fraschetti
*/

public class HttpResponseObject{
	int code;
	String body;

	public HttpResponseObject(int code, String body){
		this.code = code;
		this.body = body;
	}

	public int getCode(){
		return code;
	}

	public String getBody(){
		return body;
	}
}
