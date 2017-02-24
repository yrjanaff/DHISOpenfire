package org.jivesoftware.openfire;

//import org.jivesoftware.openfire.user.*;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

import org.jivesoftware.database.DbConnectionManager;
import org.jivesoftware.openfire.auth.Base64;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.openfire.HttpResponseObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.xmpp.packet.JID;
import org.xmpp.packet.Message;
import org.xmpp.packet.Packet;
import org.xmpp.packet.PacketError;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.*;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import org.apache.commons.httpclient.auth.AuthenticationException;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.auth.AuthProvider;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.group.*;
import org.jivesoftware.openfire.user.*;
import org.xmpp.packet.JID;

/**
 * @author Yrjan Fraschetti
 */

public class DHISMessageRouter
{
    private static final Logger log = LoggerFactory.getLogger( DHISMessageRouter.class );

    private Message packet;

    private static final String LOAD_PASSWORD =
        "SELECT plainPassword,encryptedPassword FROM ofuser WHERE username=?";

    private static final String GET_LOCATION =
        "SELECT location FROM ofdhisconversations WHERE firstuser=? AND seconduser=?";

    private static final String SET_LOCATION =
        "INSERT INTO ofdhisconversations VALUES (?, ?, ?)";

    private static final String UPDATE_COUNT =
        "UPDATE ofdhismessagecounter SET count=count+1 WHERE username=?";

    private static final String ADD_COUNT =
        "INSERT INTO ofdhismessagecounter VALUES (?, 1)";

    private static final String CHECK_COUNT =
        "SELECT username FROM ofdhismessagecounter WHERE username=?";


    public DHISMessageRouter( Message packet )
    {
        this.packet = packet;
    }

    public void sendMessageToDhis()
    {
        //Div tester her
        String username = packet.getFrom().toBareJID();
        String password = "";
        String toUser = "";
        String toPassword = "";

        log.info(username);

        username = removeHostFromUsername( username );
        toUser = removeHostFromUsername( packet.getTo().toBareJID() );

        try
        {
            password = getPassword( username );
            toPassword = getPassword( toUser );
        }
        catch ( UserNotFoundException unfe )
        {
            log.info( "UserNotfoundException....." );
        }

        log.info("Skriver ut alt!");
        log.info(username);
        log.info(password);
        log.info(toUser);
        log.info(toPassword);
        //Get id of toUser
        HttpResponseObject response = dhisHttpRequest( "me?fields=id", toUser, toPassword, "GET", null );
        String toID = "";
        if ( response.getCode() == 200 )
        {
            toID = response.getBody();
            int index = toID.indexOf( ":" ) + 2;
            toID = toID.substring( index, toID.length() - 3 );

            addCount( username );
        }

        //Build message in JSON format to send to DHIS 2 server
        String jsonBody = dhisMessage( packet.getBody(), toID, username, toUser );

        //Checking if conversation between the sender and reciever exist in db
        String location = checkConversation( toUser, username );
        int conversationCode = -1;
        if ( location.equals( "" ) )
        {
            location = checkConversation( username, toUser );
        }

        //Checking if the conversation found in db still exist in DHIS
        if ( !location.equals( "" ) )
        {
            try
            {
                HttpResponseObject dhisConversation = dhisHttpRequest( location, username, password, "GET", null );
                if ( dhisConversation.getCode() == 200 )
                {
                    conversationCode = 200;
                    jsonBody = dhisMessage( packet.getBody() );
                }
            }
            catch(Exception e){
                log.info("exception når prøvde å finne conversation!!!");
                log.info(e.toString());
                conversationCode = -1;
            }
        }

        if ( conversationCode != 200 )
        {
            location = "messageConversations/";
        }

        //Send message to DHIS 2
        HttpResponseObject messageResponse = dhisHttpRequest( location, username, password, "POST", jsonBody );

        //Set location of conversation in DB
        if ( location.equals( "messageConversations/" ) )
        {
            setConversation( username, toUser, messageResponse.getLocation() );
        }

    }

    private void addCount(String username)
    {
        log.info("Inside add count. Username: " + username);
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try
        {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement( CHECK_COUNT );
            pstmt.setString( 1, username );
            rs = pstmt.executeQuery();
            if( !rs.next() ){}

            if(rs.getString(1) != null){
                log.info("Inside if in addCount!!");
                log.info(rs.getString(1));
                updateCount(username);
            }
            else{
                log.info("Inside else in addCount");
                addNewCount(username);
            }
        }
        catch ( SQLException sqle )
        {
            log.info( "SQLException.... : " + sqle.toString() );
            addNewCount(username);
        }
        finally
        {
            DbConnectionManager.closeConnection( rs, pstmt, con );
        }
    }

    private void addNewCount( String username ){
        log.info("Inisde addNewCount");
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try
        {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement( ADD_COUNT );
            pstmt.setString( 1, username );
            rs = pstmt.executeQuery();
            if( !rs.next() ){}
        }
        catch ( SQLException sqle )
        {
            log.info( "SQLException.... : " + sqle.toString() );
        }
        finally
        {
            DbConnectionManager.closeConnection( rs, pstmt, con );
        }
    }

    private void updateCount( String username ){
        log.info("Inisde updateCount");
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try
        {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement( UPDATE_COUNT );
            pstmt.setString( 1, username );
            rs = pstmt.executeQuery();
            if( !rs.next() ){}
        }
        catch ( SQLException sqle )
        {
            log.info( "SQLException.... : " + sqle.toString() );
        }
        finally
        {
            DbConnectionManager.closeConnection( rs, pstmt, con );
        }
    }

    private void setConversation( String fromUser, String toUser, String location )
    {
        log.info( "Inni setLocation" );

        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try
        {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement( SET_LOCATION );
            pstmt.setString( 1, toUser );
            pstmt.setString( 2, fromUser );
            pstmt.setString( 3, location );
            rs = pstmt.executeQuery();
            if ( !rs.next() )
            { }
        }

        catch ( SQLException sqle )
        {
            log.info( "SQLException.... : " + sqle.toString() );
        }
        finally
        {
            DbConnectionManager.closeConnection( rs, pstmt, con );
        }
    }

    private String checkConversation( String fromUser, String toUser )
    {
        log.info( "INNI ckeckConversation" );
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        String location = "";

        try
        {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement( GET_LOCATION );
            pstmt.setString( 1, toUser );
            pstmt.setString( 2, fromUser );
            rs = pstmt.executeQuery();
            if ( !rs.next() )
            { }
            location = rs.getString( 1 );
        }

        catch ( SQLException sqle )
        {
            log.info( "SQLException.... : " + sqle.toString() );
            location = "";
        }
        finally
        {
            DbConnectionManager.closeConnection( rs, pstmt, con );
        }
        return location;
    }

    private String dhisMessage( String message, String toID, String username, String toUser )
    {
        return "{\"subject\": \"Chatlog " + username + " / " + toUser + "\",\"text\": \"" + message + "\",\"users\": [{\"id\": \"" + toID + "\"}]}";
    }

    private String dhisMessage( String message ){
        return message;
    }

    private HttpResponseObject dhisHttpRequest( String urlE, String username, String password, String requestMethod, String jsonBody )
    {
        String dhisURL = "https://yj-dev.dhis2.org/dhis/api/me";
        String authStr = username + ":" + password;
        String authEncoded = Base64.encodeBytes( authStr.getBytes() );
        String location = "";
        int code = -1;
        String body = "";
        HttpResponseObject hro = null;
        acceptHost();


        HttpURLConnection connection = null;
        try
        {
            URL url = new URL( dhisURL + urlE/*"me/?fields=id"*/ );
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestProperty( "Authorization", "Basic " + authEncoded );
            connection.setRequestProperty( "Accept", "application/json" );
            connection.setRequestMethod( requestMethod );
            connection.setDoInput( true );
            if ( requestMethod.equals( "GET" ) && jsonBody == null )
            {
                connection.setConnectTimeout( 1500 );
                connection.setInstanceFollowRedirects( false );
                connection.connect();
            }

            if ( requestMethod.equals( "POST" ) && jsonBody != null )
            {
                connection.setRequestProperty( "Content-Type", "application/json" );
                connection.setConnectTimeout( 5000 );
                connection.setDoOutput( true );
                OutputStream os = connection.getOutputStream();
                os.write( jsonBody.getBytes() );
                os.flush();

                location = connection.getHeaderFields().get( "Location" ).get( 0 );
            }

            code = connection.getResponseCode();
            body = readInputStream( connection.getInputStream() );

            hro = new HttpResponseObject( code, body, location );
        }
        catch ( SocketTimeoutException e )
        {
            log.info( "Socket time out " );
            e.printStackTrace();
            //return false;
        }
        catch ( MalformedURLException e )
        {
            log.info( "malformed" );
            e.printStackTrace();
            //return false;
        }
        catch ( AuthenticationException e )
        {
            log.info( "authentication" );
            e.printStackTrace();
            //return false;

        }
        catch ( IOException one )
        {
            log.info( "ioe" );
            log.info( one.toString() );
            //return false;
        }
        catch ( Exception e )
        {
            e.printStackTrace();
            log.info( "excepton" );
            //return false;
        }
        finally
        {
            log.info( "FINNALY" );
            if ( connection != null )
            {
                connection.disconnect();
            }
        }
        return hro;
    }

    private String removeHostFromUsername( String username )
    {
        String un = username;
        if ( un.contains( "@" ) )
        {
            int index = un.indexOf( "@" );
            un = un.substring( 0, index );
        }
        return un;
    }

    private static void acceptHost()
    {
        try
        {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[]{ new X509TrustManager()
            {
                public void checkClientTrusted( java.security.cert.X509Certificate[] chain, String authType )
                { }

                public void checkServerTrusted( java.security.cert.X509Certificate[] chain, String authType )
                { }

                public java.security.cert.X509Certificate[] getAcceptedIssuers()
                {
                    return null;
                }

                public void checkClientTrusted( X509Certificate[] certs, String authType )
                { }

                public void checkServerTrusted( X509Certificate[] certs, String authType )
                { }
            } };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance( "SSL" );
            sc.init( null, trustAllCerts, new java.security.SecureRandom() );
            HttpsURLConnection.setDefaultSSLSocketFactory( sc.getSocketFactory() );

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier()
            {
                public boolean verify( String hostname, SSLSession session )
                {
                    return true;
                }
            };

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier( allHostsValid );
        }
        catch ( NoSuchAlgorithmException e )
        {
            e.printStackTrace();
        }
        catch ( KeyManagementException e )
        {
            e.printStackTrace();
        }
    }

    private String getPassword( String username ) throws UserNotFoundException
    {
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        if ( username.contains( "@" ) )
        {
            // Check that the specified domain matches the server's domain
            int index = username.indexOf( "@" );
            String domain = username.substring( index + 1 );
            if ( domain.equals( XMPPServer.getInstance().getServerInfo().getXMPPDomain() ) )
            {
                username = username.substring( 0, index );
            }
            else
            {
                // Unknown domain.
                throw new UserNotFoundException();
            }
        }
        try
        {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement( LOAD_PASSWORD );
            pstmt.setString( 1, username );
            rs = pstmt.executeQuery();
            if ( !rs.next() )
            {
                throw new UserNotFoundException( username );
            }
            String plainText = rs.getString( 1 );

            if ( plainText == null )
            {
                throw new UnsupportedOperationException();
            }
            return plainText;
        }
        catch ( SQLException sqle )
        {
            throw new UserNotFoundException( sqle );
        }
        finally
        {
            DbConnectionManager.closeConnection( rs, pstmt, con );
        }
    }

    private String readInputStream( InputStream stream ) throws IOException
    {
        BufferedReader reader = new BufferedReader( new InputStreamReader( stream ) );
        StringBuilder builder = new StringBuilder();
        try
        {
            String line;
            while ( (line = reader.readLine()) != null )
            {
                builder.append( line );
                builder.append( '\n' );
            }
            reader.close();
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
        return builder.toString();
    }
}
