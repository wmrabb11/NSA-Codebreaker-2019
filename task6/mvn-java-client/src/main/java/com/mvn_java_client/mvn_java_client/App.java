package com.mvn_java_client.mvn_java_client;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.javatuples.Pair;
import org.jivesoftware.smack.AbstractXMPPConnection;
import org.jivesoftware.smack.ReconnectionManager;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration.Builder;
import org.jivesoftware.smackx.vcardtemp.VCardManager;
import org.jivesoftware.smackx.vcardtemp.packet.VCard;
import org.json.JSONArray;
import org.json.JSONObject;
import org.jxmpp.jid.EntityBareJid;
import org.jxmpp.jid.impl.JidCreate;

public class App {

    private static final SecretKey generateMessageKey () {
        final byte[] keyBytes = new byte[32];
        new SecureRandom().nextBytes( keyBytes );
        SecretKeySpec aes = null;
        try {
            aes = new SecretKeySpec( keyBytes, "AES" );
        }
        catch ( final Exception e ) {
            e.printStackTrace();
        }
        return aes;
    }

    public static PublicKey convertPublicPEMtoPublicKey ( final String publicKey )
            throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        final PemObject pemPubKey = new PemReader( new StringReader( publicKey ) ).readPemObject();
        if ( pemPubKey == null ) {
            return null;
        }
        return KeyFactory.getInstance( "RSA" ).generatePublic( new X509EncodedKeySpec( pemPubKey.getContent() ) );
    }

    public static String computeKeyFingerprint ( final byte[] keyBytes ) throws NoSuchAlgorithmException {
        final MessageDigest md = MessageDigest.getInstance( "SHA-256" );
        md.update( keyBytes );
        return Base64.getEncoder().encodeToString( md.digest() );
    }

    public static String wrapKey ( final PublicKey publicKey, final SecretKey secretKey )
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException {
        final Cipher keyCipher = Cipher.getInstance( "RSA/ECB/PKCS1Padding" );
        keyCipher.init( 3, publicKey );
        return Base64.getEncoder().encodeToString( keyCipher.wrap( secretKey ) );
    }

    public static byte[] generateRandom ( final int bytes ) {
        final byte[] keyBytes = new byte[bytes];
        new SecureRandom().nextBytes( keyBytes );
        return keyBytes;
    }

    public static Pair<byte[], byte[]> aesEncrypt ( final SecretKey key, final byte[] data )
            throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        final Cipher msgCipher = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
        final byte[] iv = generateRandom( 16 );
        msgCipher.init( 1, key, new IvParameterSpec( iv ) );
        return new Pair<byte[], byte[]>( iv, msgCipher.doFinal( data ) );
    }

    public static final byte[] hmacSHA256 ( final SecretKey key, final byte[] message )
            throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = Mac.getInstance( "HmacSHA256" );
        mac.init( key );
        return mac.doFinal( message );
    }

    public static String encryptMessage ( final String msg, final Set<PublicKey> clientKeys,
            final Set<PublicKey> contactKeys )
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException, BadPaddingException {
        final SecretKey msgKey = generateMessageKey();
        final HashMap<String, String> contactKeyMap = new HashMap<String, String>();
        final HashMap<String, String> clientKeyMap = new HashMap<String, String>();
        for ( final PublicKey key : contactKeys ) {
            contactKeyMap.put( computeKeyFingerprint( key.getEncoded() ), wrapKey( key, msgKey ) );
        }
        for ( final PublicKey key : clientKeys ) {
            clientKeyMap.put( computeKeyFingerprint( key.getEncoded() ), wrapKey( key, msgKey ) );
        }
        final JSONObject messageDoc = new JSONObject();
        final JSONObject msgKeys = new JSONObject();
        final JSONObject message = new JSONObject();
        final JSONObject internalMessage = new JSONObject();
        final JSONArray internalContactFingerprints = new JSONArray();
        final JSONArray internalClientFingerprints = new JSONArray();
        for ( final Entry<String, String> entry : contactKeyMap.entrySet() ) {
            msgKeys.put( entry.getKey(), entry.getValue() );
            internalContactFingerprints.put( entry.getKey() );
        }
        for ( final Entry<String, String> entry : clientKeyMap.entrySet() ) {
            msgKeys.put( entry.getKey(), entry.getValue() );
            internalClientFingerprints.put( entry.getKey() );
        }
        internalMessage.put( "ryan--vhost-254@terrortime.app", internalClientFingerprints );
        internalMessage.put( "mordechai--vhost-254@terrortime.app", internalContactFingerprints );
        internalMessage.put( "body", msg );
        final Pair<byte[], byte[]> encMsg = aesEncrypt( msgKey, internalMessage.toString().getBytes() );
        final String iv = Base64.getEncoder().encodeToString( encMsg.getValue0() );
        final byte[] messageSigBytes = hmacSHA256( msgKey, encMsg.getValue1() );
        final String encodedMsg = Base64.getEncoder().encodeToString( encMsg.getValue1() );
        final String encodedSig = Base64.getEncoder().encodeToString( messageSigBytes );
        message.put( "iv", iv );
        message.put( "msg", encodedMsg );
        messageDoc.put( "messageKey", msgKeys );
        messageDoc.put( "message", message );
        messageDoc.put( "messageSig", encodedSig );
        return messageDoc.toString();
    }

    public static String convertKeyToPEM ( final Key key ) throws IOException {
        final StringWriter stringWriter = new StringWriter();
        final PemWriter pemWriter = new PemWriter( stringWriter );
        pemWriter.writeObject( new JcaMiscPEMGenerator( key ) );
        pemWriter.flush();
        pemWriter.close();
        return stringWriter.toString();
    }

    public static KeyPair genKeyPair () throws NoSuchAlgorithmException, IOException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance( "RSA" );
        keyGen.initialize( 2048 );
        final KeyPair kPair = keyGen.generateKeyPair();
        return kPair;
    }

    public static void addKeyPair ( final String id, final KeyPair newKeyPair ) {
        AbstractXMPPConnection mConnection = null;
        ReconnectionManager mReconnectionManager = null;
        final Builder config = XMPPTCPConnectionConfiguration.builder();
        try {
            config.setUsernameAndPassword( id,
                    "2pOvoQPPCKsuCB8LNoiyiWVC_NhIJKlm--sT2Z3cxYU.9S_wQtbHHYAMiA1LXy6RqtCHjIQXDPZ4qIqEo0f7rkg" );
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
            final VCardManager vCardManager = VCardManager.getInstanceFor( mConnection );
            final EntityBareJid jid = JidCreate.entityBareFrom( id + "@terrortime.app" );
            final VCard vCard = vCardManager.loadVCard( jid );
            String pubKeys = vCard.getField( "DESC" );
            pubKeys += ":" + convertKeyToPEM( newKeyPair.getPublic() );
            vCard.setField( "DESC", pubKeys );
            vCard.save( mConnection );
            mConnection.disconnect();
        }
        catch ( final Exception e ) {
            e.printStackTrace();
        }
    }

    public static void fixRyanAccount () {
        AbstractXMPPConnection mConnection = null;
        ReconnectionManager mReconnectionManager = null;
        final Builder config = XMPPTCPConnectionConfiguration.builder();
        try {
            config.setUsernameAndPassword( "ryan--vhost-254",
                    "IbCXb675stVk83_UH48EoRRTc_KB5ypgTgFX6_zjE1A.gzgrIboojvrIbNH29QqyzEdipJ2H_jQXpzshmubdC2M" );
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
            final VCardManager vCardManager = VCardManager.getInstanceFor( mConnection );
            final EntityBareJid jid = JidCreate.entityBareFrom( "ryan--vhost-254@terrortime.app" );
            final VCard vCard = vCardManager.loadVCard( jid );
            String pubKeys = vCard.getField( "DESC" );
            final String oldKeys = "-----BEGIN PUBLIC KEY-----\n"
                    + "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQANLjJ3WDYU99L9iGNCWVRq\n"
                    + "h6nxPHwRfA97JejWKrBH1BupAC7Eb4T11iaiBOv/5k0sVdOCAuDazh6iPk9/rcUI\n"
                    + "k1wopJZ0uGQBCe0KJjjTbHIEQO5LMOlH9IeIPoSwrLpuMXwxME6OVblOjWEt30ih\n"
                    + "34Aytom9DIaZ6pJfkgK0l7ABFEa0sdULEiFr5tD4wYO6nD3G2JAOOtvSXxNasRo0\n"
                    + "wcz4H8xj63FpI3A/i6qD4K33SUzf+m6yVoE0crD+QvTb3jqWqGISHKyFIp8IHaT5\n"
                    + "Dv3pA1C5+xXD0P7BwS4bkgdq9vpSvmKI6d1TksJXuTaYJ4UV9xFT5d94Pu+oIoVJ\n" + "AgMBAAE=\n"
                    + "-----END PUBLIC KEY-----\n" + ":-----BEGIN PUBLIC KEY-----\n"
                    + "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQAHjWy8CPKhNrIyFfUC1eeD\n"
                    + "Gx3W1ogKKfDedBWSDjCPZJT3cogv6TKGtTO2WNalMLx2Q6wtdAe+i88uKatCU3El\n"
                    + "PWaHIVmRkWpMC8K/xa/HjposZ6kR2RmcH+bKrdYYs35Rj7IPf5+N24374jmS9NQR\n"
                    + "dH7sgE7m4TtYAtdUZITEhU2Xy2qjZE+1tSPbzfz7f4Z2KNP4PpmEdu5MTSGmbOHc\n"
                    + "ITiaQZmzjoSN68aDTph6kyJPeUuKoqq2DBaa/XAi3yWX8c0X9CxD2N05hzfGs0ny\n"
                    + "jr+LtVuuVHTszUtv0WcyOV71CSBCf0ez8pqEEQyF1PAH/0KArGUzS7l4eomG9HuF\n" + "AgMBAAE=\n"
                    + "-----END PUBLIC KEY-----";
            pubKeys += ":" + oldKeys;
            vCard.setField( "DESC", pubKeys );
            vCard.save( mConnection );
            mConnection.disconnect();
        }
        catch ( final Exception e ) {
            e.printStackTrace();
        }
    }

    public static void main ( final String[] args ) throws NoSuchAlgorithmException, IOException {
        /*
         * Generate new key pair and add it to all the users to read their
         * messages later ;)
         */
        // final KeyPair newKeyPair = genKeyPair();
        // System.out.println( "Private key: " + convertKeyToPEM(
        // newKeyPair.getPrivate() ) );
        // System.out.println( "Public key: " + convertKeyToPEM(
        // newKeyPair.getPublic() ) );
        final ArrayList<String> usernameArr = new ArrayList<String>();
        // Org Leader
        usernameArr.add( "ryan" );
        // Cell Leader #1
        usernameArr.add( "mordechai" );
        // Cell Leader #1's employees
        usernameArr.add( "maximiliano" );
        usernameArr.add( "levi" );
        // Cell Leader #2
        usernameArr.add( "eva" );
        // Cell Leader #2's employees
        usernameArr.add( "alisa" );
        usernameArr.add( "greyson" );
        // Cell Leader #3
        usernameArr.add( "eli" );
        // Cell Leader #3's employees
        usernameArr.add( "nova" );
        usernameArr.add( "wyatt" );

        /**
         * for ( final String username : usernameArr ) { final String
         * fullUsername = username + "--vhost-254"; addKeyPair( fullUsername,
         * newKeyPair ); }
         */

        fixRyanAccount();
        /*
         * Get the list of previous messages
         */
        // mMamManager = MamManager.getInstanceFor( mConnection );
        // final MamQueryArgs mamArgs =
        // MamQueryArgs.builder().setResultPageSize( 50
        // ).queryLastPage().build();
        // final MamQuery mamQuery = mMamManager.queryArchive( mamArgs );
        // System.out.println( "Message count: " +
        // mamQuery.getMessageCount() );
        // for ( int i = 0; i < mamQuery.getMessageCount(); i++ ) {
        // final Message m = mamQuery.getMessages().get( i );
        // System.out.println( "To: " + m.getTo() );
        // System.out.println( "From: " + m.getFrom() );
        // System.out.println( "Body: " + m.getBody() );
        // }

        /*
         * Send a spoofed message
         */
        // final Set<PublicKey> contactKeys = new HashSet<PublicKey>();
        // final Set<PublicKey> clientKeys = new HashSet<PublicKey>();
        // final EntityBareJid jid = JidCreate.entityBareFrom(
        // "mordechai--vhost-254@terrortime.app" );
        // final VCardManager vCardManager = VCardManager.getInstanceFor(
        // mConnection );
        // final VCard vCard = vCardManager.loadVCard( jid );
        // final String publicKey = vCard.getField( "DESC" );
        // Get Mordechai's public key, which produces the same key signature
        // as previous messages
        // final String firstKey = publicKey.split( ":" )[1];
        // final PublicKey pubKey = convertPublicPEMtoPublicKey( firstKey );
        // contactKeys.add( pubKey );
        // final EntityBareJid ryanJid = JidCreate.entityBareFrom(
        // "ryan--vhost-254@terrortime.app" );
        // final VCard ryanVCard = vCardManager.loadVCard( ryanJid );
        // final String ryanOldPubKey = ryanVCard.getField( "DESC" );
        // Make note of Ryan's old public keys (in case u fuck up)
        // System.out.println( "Ryan old public keys: " + ryanOldPubKey );
        // final PublicKey ryanNewPubKey = genKeyPair();
        // Replace his public keys with yours
        // System.out.println( "Ryan new public key: " + convertKeyToPEM(
        // ryanNewPubKey ) );
        // ryanVCard.setField( "DESC", convertKeyToPEM( ryanNewPubKey ) );
        // ryanVCard.save( mConnection );
        // clientKeys.add( ryanNewPubKey );
        // final Message msg = new Message();
        // msg.setTo( jid );
        // msg.setFrom( ryanJid );
        // msg.setBody( encryptMessage( "hello", clientKeys, contactKeys )
        // );
        // System.out.println( "To: " + msg.getTo() );
        // System.out.println( "From: " + msg.getFrom() );
        // System.out.println( "Body: " + msg.getBody() );
        // mChatManager = ChatManager.getInstanceFor( mConnection );
        // mChat = mChatManager.chatWith( jid );
        // mChat.send( msg );

    }
}
