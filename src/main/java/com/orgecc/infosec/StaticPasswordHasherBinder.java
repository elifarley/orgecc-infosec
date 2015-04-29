package com.orgecc.infosec;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import com.orgecc.infosec.PasswordKit.HashType;
import com.orgecc.infosec.PasswordKit.PasswordHasher;

class StaticPasswordHasherBinder {

    private StaticPasswordHasherBinder() {
        // Classe utilit�ria
    }

    private static final ImmutableMap<HashType, PasswordHasher> PASSWORD_HASHERS = Maps
            .immutableEnumMap( ImmutableMap.<HashType, PasswordHasher> builder()
                    .put( HashType.BCRYPT, PasswordKitBCryptHMAC.PH_BCRYPT )
                    .put( HashType.BCRYPTHMAC, PasswordKitBCryptHMAC.PH_BCRYPTHMAC ).build() );

    public static ImmutableMap<HashType, PasswordHasher> getPasswordHashers() {
        return PASSWORD_HASHERS;
    }
}
