package com.ionic.sdk.addon.tomcat.ionic;

import com.ionic.sdk.crypto.secretshare.SecretShareData;
import com.ionic.sdk.crypto.secretshare.SecretSharePersistor;
import com.ionic.sdk.device.profile.DeviceProfile;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorPlainText;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorSecretShare;
import com.ionic.sdk.device.profile.persistor.ProfilePersistor;
import com.ionic.sdk.error.IonicException;
import com.ionic.sdk.error.SdkData;
import com.ionic.sdk.error.SdkError;

import java.io.File;
import java.util.List;

/**
 * This class is used by the code sample to perform a protection conversion on a serialized Ionic Secure Enrollment
 * Profile (SEP).  The code sample prerequisites include a plaintext SEP.  In the
 * {@link DeviceProfilePersistorPlainText} format, the secrets used by the active device profile to communicate with
 * the Ionic platform are unprotected.  In the {@link DeviceProfilePersistorSecretShare} format, the communication
 * secrets are protected using an AES key derived from the process environment.
 */
public class ProfilePersistorUtil {

    /**
     * The code sample is intended to be initialized with a persisted plaintext Secure Enrollment Profile (SEP).  This
     * method generates a secret derived from the process environment, and uses that secret to encrypt the SEP
     * data.  The encrypted data is then persisted to the specified filesystem path.  The plaintext file is left in
     * place.
     * <p>
     * If the secret share data has already been persisted, the secret generation step is skipped.
     *
     * @param ionicProfilePlainText   the filesystem path of the (input) plaintext Ionic Secure Enrollment Profile
     * @param ionicProfileSecretShare the filesystem path of the (output) protected Ionic Secure Enrollment Profile
     * @throws IonicException on serialization failures during the data conversion
     */
    public static void convertFromPlaintext(
            final File ionicProfilePlainText, final File ionicProfileSecretShare) throws IonicException {
        // skip data generation if it already exists
        if (!ionicProfileSecretShare.exists()) {
            // if secret share data doesn't exist, we need data from persisted plaintext SEP
            SdkData.checkTrue(ionicProfilePlainText.exists(), SdkError.ISAGENT_OPENFILE);
            // load plaintext data
            final ProfilePersistor profilePersistorPlainText =
                    new DeviceProfilePersistorPlainText(ionicProfilePlainText.getPath());
            final String[] activeProfiles = new String[1];
            final List<DeviceProfile> deviceProfiles = profilePersistorPlainText.loadAllProfiles(activeProfiles);
            final String activeProfile = activeProfiles[0];
            // save secret share data
            final ProfilePersistor profilePersistorSecretShare = getPersistorSecretShare(ionicProfileSecretShare);
            profilePersistorSecretShare.saveAllProfiles(deviceProfiles, activeProfile);
        }
    }

    /**
     * Generate a {@link ProfilePersistor}, initialized with the AES key generated from the process environment data.
     *
     * @param ionicProfileSecretShare the filesystem path of the (output) protected Ionic Secure Enrollment Profile
     * @return the configured {@link DeviceProfilePersistorSecretShare} to be used by the Ionic client library
     * @throws IonicException on failures during cryptography initialization, or on invalid method input
     */
    public static ProfilePersistor getPersistorSecretShare(final File ionicProfileSecretShare) throws IonicException {
        // derive the filename for the persisted secret share data from the filename for the profile
        final String filenameProfile = ionicProfileSecretShare.getName();
        final String filenameSecretShareData = filenameProfile.replace("sep", "secret");
        SdkData.checkTrue(filenameProfile.equals(filenameSecretShareData), SdkError.ISAGENT_INVALIDVALUE);
        final File ionicFileSecretShare = new File(ionicProfileSecretShare.getParent(), filenameSecretShareData);
        // configure the ProfilePersistor
        final SecretShareData secretShareData = new SecretShareDataSample();
        final SecretSharePersistor secretSharePersistor =
                new SecretSharePersistor(ionicFileSecretShare.getPath(), secretShareData);
        final DeviceProfilePersistorSecretShare profilePersistor =
                new DeviceProfilePersistorSecretShare(secretSharePersistor);
        profilePersistor.setFilePath(ionicProfileSecretShare.getPath());
        return profilePersistor;
    }
}
