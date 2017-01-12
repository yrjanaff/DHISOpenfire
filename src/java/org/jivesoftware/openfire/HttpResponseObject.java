package org.jivesoftware.openfire;

/**
 * @author Yrjan Fraschetti
 */

public class HttpResponseObject
{
    int code;
    String body;
    String location;

    public HttpResponseObject( int code, String body, String location )
    {
        this.code = code;
        this.body = body;
        this.location = location;
    }

    public int getCode()
    {
        return code;
    }

    public String getBody()
    {
        return body;
    }

    public String getLocation()
    {
        return location;
    }
}
