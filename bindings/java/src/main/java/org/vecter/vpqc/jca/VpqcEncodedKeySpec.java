package org.vecter.vpqc.jca;

import java.security.spec.EncodedKeySpec;

/** A key in the vpqc binary encoding (format {@code "VPQC"}), for {@code KeyFactory}. */
public final class VpqcEncodedKeySpec extends EncodedKeySpec {
    /**
     * @param encoded the vpqc key encoding
     */
    public VpqcEncodedKeySpec(byte[] encoded) {
        super(encoded);
    }

    @Override
    public String getFormat() {
        return VpqcKeys.FORMAT;
    }
}
