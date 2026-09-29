package org.vecter.vpqc.jca;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import org.vecter.vpqc.Profile;

/**
 * Selects the vpqc profile for key generation.
 *
 * @param profile the profile
 */
public record VpqcParameterSpec(Profile profile) implements AlgorithmParameterSpec {
    /** Creates the spec. */
    public VpqcParameterSpec {
        Objects.requireNonNull(profile, "profile");
    }
}
