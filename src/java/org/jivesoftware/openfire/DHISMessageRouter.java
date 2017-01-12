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
        log.info( "Inside DHISMessageRouter!!!! Message packet will follow:" );
        log.info( "Body: " + packet.getBody() + " From: " + packet.getFrom().toBareJID() + " To: " + packet.getTo().toBareJID() );

        username = removeHostFromUsername( username );
        toUser = removeHostFromUsername( packet.getTo().toBareJID() );

        log.info( "Fetching password for users" );
        try
        {
            password = getPassword( username );
            toPassword = getPassword( toUser );
        }
        catch ( UserNotFoundException unfe )
        {
            log.info( "UserNotfoundException....." );
        }

        //Get id of toUser
        HttpResponseObject response = dhisHttpRequest( "me?fields=id", toUser, toPassword, "GET", null );
        String toID = "";
        if ( response.getCode() == 200 )
        {
            toID = response.getBody();
            int index = toID.indexOf( ":" ) + 2;
            toID = toID.substring( index, toID.length() - 3 );
        }
        log.info( "ID for user: " + toUser );
        log.info( toID );

        //Build message in JSON format to send to DHIS 2 server
        String jsonBody = dhisMessage( packet.getBody(), toID, username, toUser );
        log.info( jsonBody );

        //Checking if conversation between the sender and reciever exist in db
        log.info( "checkConversation" );
        String location = checkConversation( toUser, username );
        int conversationCode = -1;
        if ( location.equals( "" ) )
        {
            log.info( "location was not found on first try. Swapping usernames and checking again." );
            location = checkConversation( username, toUser );
        }
        log.info( "checkConversation returned: " + location );

        //Checking if the conversation found in db still exist in DHIS
        if ( !location.equals( "" ) )
        {
            log.info( "Sjekker om conversation fortsatt finnes i DHIS" );
            HttpResponseObject dhisConversation = dhisHttpRequest( location, username, password, "GET", null );
            log.info( "DHIS sier at conversation er: " + dhisConversation.getCode() );
            if ( dhisConversation.getCode() == 200 )
            {
                conversationCode = 200;
                log.info( "saved conversationCode" );
            }
        }

        if ( conversationCode != 200 )
        {
            log.info( "ConversationCode was not 200, resetting location to messageConversations/" );
            location = "messageConversations/";
        }

        //Send message to DHIS 2
        log.info( "Sending message to DHIS2!" );
        HttpResponseObject messageResponse = dhisHttpRequest( location, username, password, "POST", jsonBody );
        log.info( "Message sent. ResponseCode: " + messageResponse.getCode() );
        log.info( "Body: " + messageResponse.getBody() );

        //Set location of conversation in DB
        if ( location.equals( "messageConversations/" ) )
        {
            setConversation( username, toUser, messageResponse.getLocation() );
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
            {
                log.info( "mulig noe skjedde nå?" );
            }
            log.info( "Ser om rs skriver ut en insert etter insert: " + rs.getString( 1 ) );
        }

        catch ( SQLException sqle )
        {
            log.info( "SQLException.... : " + sqle.toString() );
        }
        finally
        {
            DbConnectionManager.closeConnection( rs, pstmt, con );
        }
        log.info( "Mulig det gikk å lagre location i db!" );
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
            {
                log.info( "mulig noe skjedde nå?" );
            }
            location = rs.getString( 1 );
            log.info( "Skriver ut location for å være sikker: " + location );
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

    private HttpResponseObject dhisHttpRequest( String urlE, String username, String password, String requestMethod, String jsonBody )
    {
        String dhisURL = "https://yj-dev.dhis2.org/dhis/api/";
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
            log.info( "Inne i connection try" );
            URL url = new URL( dhisURL + urlE/*"me/?fields=id"*/ );
            log.info( "Før connection: url: " + url );
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestProperty( "Authorization", "Basic " + authEncoded );
            connection.setRequestProperty( "Accept", "application/json" );
            connection.setRequestMethod( requestMethod );
            connection.setDoInput( true );
            if ( requestMethod.equals( "GET" ) && jsonBody == null )
            {
                log.info( "Inside GET in dhisHttpRequest" );
                connection.setConnectTimeout( 1500 );
                connection.setInstanceFollowRedirects( false );
                connection.connect();
            }

            if ( requestMethod.equals( "POST" ) && jsonBody != null )
            {
                log.info( "Inside POST in dhisHttpRequest" );
                connection.setRequestProperty( "Content-Type", "application/json" );
                connection.setConnectTimeout( 5000 );
                connection.setDoOutput( true );
                OutputStream os = connection.getOutputStream();
                os.write( jsonBody.getBytes() );
                os.flush();

                location = connection.getHeaderFields().get( "Location" ).get( 0 );
            }

            log.info( "ÅPNET CONNECTION: url- " + url );

            code = connection.getResponseCode();
            body = readInputStream( connection.getInputStream() );

            hro = new HttpResponseObject( code, body, location );
            log.info( "CODE: " + code );
            log.info( "BODY: " + body );
            log.info( "LOCATION: " + location );
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
                {
                }

                public void checkServerTrusted( java.security.cert.X509Certificate[] chain, String authType )
                {
                }

                public java.security.cert.X509Certificate[] getAcceptedIssuers()
                {
                    return null;
                }

                public void checkClientTrusted( X509Certificate[] certs, String authType )
                {
                }

                public void checkServerTrusted( X509Certificate[] certs, String authType )
                {
                }
            }
            };

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
        /*if (!supportsPasswordRetrieval()) {
            // Reject the operation since the provider is read-only
            throw new UnsupportedOperationException();
        }*/
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
            /*String encrypted = rs.getString(2);
            if (encrypted != null) {
                try {
                    return AuthFactory.decryptPassword(encrypted);
                }
                catch (UnsupportedOperationException uoe) {
                    // Ignore and return plain password instead.
                }
            }*/
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
