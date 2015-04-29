package com.orgecc.infosec;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Stopwatch;
import com.google.common.io.BaseEncoding;
import com.orgecc.infosec.PasswordKit.HashType;
import com.orgecc.infosec.PasswordKit.PasswordHasher;

class PasswordKitBCryptHMAC {

    static final PasswordHasher PH_BCRYPT = new PasswordHasher() {

        @Override
        public String hashpw( final String plaintext ) {
            return PasswordKitBCryptHMAC.hashpwBCrypt( plaintext );
        }

        @Override
        public boolean checkpw( final String plaintext, final String hashed ) {
            return PasswordKitBCryptHMAC.checkpwBCrypt( plaintext, hashed );
        }
    };

    static final PasswordHasher PH_BCRYPTHMAC = new PasswordHasher() {

        @Override
        public String hashpw( final String plaintext ) {
            return PasswordKitBCryptHMAC.hashpwBCryptHMAC( plaintext );
        }

        @Override
        public boolean checkpw( final String plaintext, final String hashed ) {
            return PasswordKitBCryptHMAC.checkpwBCryptHMAC( plaintext, hashed );
        }

    };

    private final static Logger LOGGER = LoggerFactory.getLogger( PasswordKitBCryptHMAC.class );

    private final static int LOG2_ROUNDS;

    private final static SecretKeySpec PEPPER_KEY_SPEC;

    private static final String DEFAULT_ENCODING = "UTF-8";

    /**
     * 384 bits are 48 bytes ~ 64 chars in Base64, which is less than BCrypt's 72 length limit
     */
    private static final String HMAC = "HmacSHA384";

    static {

        try {
            final Properties p = new Properties();
            final InputStream in =
                    PasswordKitBCryptHMAC.class.getResourceAsStream( "/passwordkit-bh.properties" );
            if ( in == null ) {
                final String msg = "Missing classpath resource '/passwordkit-bh.properties'";
                LOGGER.error( msg );
                throw new NullPointerException( msg );
            }
            p.load( in );

            final byte[] keyBytes =
                    javax.xml.bind.DatatypeConverter.parseHexBinary( p.getProperty( "pepper" ) );
            if ( keyBytes.length != 48 ) {
                throw new RuntimeException( "Expected 48 bytes but got " + keyBytes.length );
            }
            PEPPER_KEY_SPEC = new SecretKeySpec( keyBytes, HMAC );

            LOG2_ROUNDS =
                    computeLog2Rounds( Integer.valueOf( (String) p.get( "min-delay-in-millis" ) ) );

        } catch ( final Exception e ) {
            throw new RuntimeException( "Error while initializing class", e );
        }
    }

    private PasswordKitBCryptHMAC() {
        // Classe utilit�ria
    }

    private static int computeLog2Rounds( final long minDelayInMillis ) {

        final Stopwatch stopwatch = Stopwatch.createUnstarted();

        for ( int log2Rounds = 10; log2Rounds < 100000; log2Rounds++ ) {

            final String hashed = BCrypt.hashpw( HMAC, BCrypt.gensalt( log2Rounds ) );
            stopwatch.reset();

            stopwatch.start();
            if ( !BCrypt.checkpw( HMAC, hashed ) ) {
                throw new IllegalArgumentException();
            }
            final long elapsed = stopwatch.elapsed( TimeUnit.MILLISECONDS );

            LOGGER.info( String.format( "[INFOSEC] Log2 BCrypt Rounds: %d; Elapsed: %dms",
                    log2Rounds, elapsed ) );

            if ( elapsed >= minDelayInMillis ) {
                return log2Rounds;
            }
        }

        throw new IllegalArgumentException();

    }

    public static String hashpwBCrypt( final String password ) {
        if ( password.length() > HashType.BCRYPT.getMaxPlaintextCharCount() ) {
            throw new IllegalArgumentException( "https://news.ycombinator.com/item?id=4515894" );
        }
        return BCrypt.hashpw( password, BCrypt.gensalt( LOG2_ROUNDS ) );
    }

    public static String hashpwBCryptHMAC( final String password ) {
        return hashpwBCrypt( hmacAsBase64( password, PEPPER_KEY_SPEC ) );
    }

    public static boolean checkpwBCrypt( final String plaintext, final String hashed ) {
        return BCrypt.checkpw( plaintext, hashed );
    }

    public static boolean checkpwBCryptHMAC( final String plaintext, final String hashed ) {
        return checkpwBCrypt( hmacAsBase64( plaintext, PEPPER_KEY_SPEC ), hashed );
    }

    private static String hmacAsBase64( final String value, final SecretKeySpec key ) {
        return BaseEncoding.base64().encode( hmac( value, key ) );
    }

    /**
     * @see http://www.michaelwilliams.co.za/hmac-sha512-in-java/
     *
     */
    private static byte[] hmac( final String value, final String key ) {
        try {
            final SecretKeySpec keySpec =
                    new SecretKeySpec( key.getBytes( DEFAULT_ENCODING ), HMAC );
            return hmac( value, keySpec );

        } catch ( final UnsupportedEncodingException e ) {
            throw new RuntimeException( e );
        }

    }

    private static byte[] hmac( final String value, final SecretKeySpec keySpec ) {
        try {

            final Mac mac = Mac.getInstance( HMAC );
            mac.init( keySpec );
            return mac.doFinal( value.getBytes( DEFAULT_ENCODING ) );

        } catch ( final NoSuchAlgorithmException e ) {
            throw new RuntimeException( e );
        } catch ( final InvalidKeyException e ) {
            throw new RuntimeException( e );
        } catch ( final UnsupportedEncodingException e ) {
            throw new RuntimeException( e );
        }
    }

}
