package com.mvn_java_client.mvn_java_client;

import java.net.InetAddress;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

import org.jivesoftware.smack.AbstractXMPPConnection;
import org.jivesoftware.smack.ReconnectionManager;
import org.jivesoftware.smack.packet.ExtensionElement;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration.Builder;
import org.jivesoftware.smackx.mam.MamManager;
import org.jivesoftware.smackx.mam.MamManager.MamQuery;
import org.jivesoftware.smackx.mam.MamManager.MamQueryArgs;

public class App {
    public static void main ( final String[] args ) {
        AbstractXMPPConnection mConnection = null;
        ReconnectionManager mReconnectionManager = null;
        MamManager mMamManager = null;
        final Builder config = XMPPTCPConnectionConfiguration.builder();
        try {
            // Replace password with a valid token from masq.py
            config.setUsernameAndPassword( "ryan--vhost-254",
                    "agUxEwAtsKf4_dCvIO1oRZ0dML2E5xinLIfOngTSN-U.Yn5s2pfCw3HIqjK86dO-pxi2R5xXUcTMIIFSW8_dKe4" );
            config.setResource( "chat" );
            config.setHostAddress( InetAddress.getByName( "chat.terrortime.app" ) );
            config.setXmppDomain( "terrortime.app" );
            config.setPort( 443 );
            config.setHostnameVerifier( new HostnameVerifier() {
                public boolean verify ( final String hostname, final SSLSession session ) {
                    return true;
                }
            } );
            config.setCustomX509TrustManager( new X509TrustManager() {
                public void checkClientTrusted ( final X509Certificate[] chain, final String authType )
                        throws CertificateException {
                }

                public void checkServerTrusted ( final X509Certificate[] chain, final String authType )
                        throws CertificateException {
                }

                public X509Certificate[] getAcceptedIssuers () {
                    return new X509Certificate[0];
                }
            } );
            mConnection = new XMPPTCPConnection( config.build() );
            mConnection.setReplyTimeout( 30000 );
            mConnection.connect();
            mConnection.login();
            mReconnectionManager = ReconnectionManager.getInstanceFor( mConnection );
            mReconnectionManager.enableAutomaticReconnection();
            mMamManager = MamManager.getInstanceFor( mConnection );
            final MamQueryArgs mamArgs = MamQueryArgs.builder().setResultPageSize( 50 ).queryLastPage().build();
            final MamQuery mamQuery = mMamManager.queryArchive( mamArgs );
            System.out.println( "Message count: " + mamQuery.getMessageCount() );
            for ( int i = 0; i < mamQuery.getMessageCount(); i++ ) {
                final Message m = mamQuery.getMessages().get( i );
                final List<ExtensionElement> elems = m.getExtensions();
                for ( int j = 0; j < elems.size(); j++ ) {
                    System.out.println( "Extension: " + elems.get( j ).getElementName() );
                    System.out.println( "Namespace: " + elems.get( j ).getNamespace() );
                    System.out.println( "Class: " + elems.get( j ).getClass() );
                }
                System.out.println( "To: " + m.getTo() );
                System.out.println( "From: " + m.getFrom() );
                System.out.println( "Body: " + m.getBody() );
            }
            mConnection.disconnect();
        }
        catch ( final Exception e ) {
            e.printStackTrace();
        }
    }
}
