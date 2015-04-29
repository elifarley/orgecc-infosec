package com.orgecc.infosec;

import java.util.Map;

import org.apache.commons.lang3.StringUtils;

public class PasswordKit {

    private PasswordKit() {
        // Classe utilit�ria
    }

    public interface PasswordHasher {

        String hashpw( String plaintext );

        boolean checkpw( String plaintext, String hashed );

    }

    public enum HashType implements PasswordHasher {

        /**
         * M�x: 8 caracteres
         */
        UNIX_CRYPT( 8, 13 ),

        /**
         * M�x: 72 caracteres
         */
        BCRYPT( 72, 60 ),

        /**
         * M�x: 2^16 - 1 caracteres.
         *
         * @see {@link PasswordKitBCryptHMAC#hashpwBCryptHMAC(String, String)}
         */
        BCRYPTHMAC( 2 ^ 16 - 1, 60 );

        private static Map<HashType, PasswordHasher> PASSWORD_HASHERS = StaticPasswordHasherBinder
                .getPasswordHashers();

        private final int maxPlaintextCharCount;

        private final int outputCharCount;

        HashType( final int maxPlaintextCharCount, final int outputCharCount ) {
            this.maxPlaintextCharCount = maxPlaintextCharCount;
            this.outputCharCount = outputCharCount;
        }

        public int getMaxPlaintextCharCount() {
            return this.maxPlaintextCharCount;
        }

        public int getOutputCharCount() {
            return this.outputCharCount;
        }

        @Override
        public String hashpw( final String plaintext ) {

            if ( StringUtils.isBlank( plaintext ) ) {
                throw new IllegalArgumentException( "Senha vazia" );
            }

            return PASSWORD_HASHERS.get( this ).hashpw( plaintext );

        }

        @Override
        public boolean checkpw( final String plaintext, final String hashed ) {

            if ( StringUtils.isBlank( plaintext ) || StringUtils.isBlank( hashed ) ) {
                return false;
            }

            return PASSWORD_HASHERS.get( this ).checkpw( plaintext, hashed );

        }

    }

}
