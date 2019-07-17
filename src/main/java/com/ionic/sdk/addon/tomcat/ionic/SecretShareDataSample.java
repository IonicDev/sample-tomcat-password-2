package com.ionic.sdk.addon.tomcat.ionic;

import com.ionic.sdk.agent.service.IDC;
import com.ionic.sdk.core.value.Value;
import com.ionic.sdk.core.vm.Network;
import com.ionic.sdk.crypto.env.Environment;
import com.ionic.sdk.crypto.secretshare.SecretShareBucket;
import com.ionic.sdk.crypto.secretshare.SecretShareData;
import com.ionic.sdk.error.IonicException;

import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Properties;

/**
 * Implementation of {@link SecretShareData} interface, needed when using
 * {@link com.ionic.sdk.crypto.secretshare.SecretSharePersistor}.
 * <p>
 * SecretSharePersistor protects a persisted Ionic Secure Enrollment Profile (SEP) using selected values from the
 * process environment.  It folds these values together into the source material for an AES key, which is then used to
 * encrypt the SEP content.  The internal algorithm is based on
 * <a href="https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing">Shamir's Secret Sharing</a>.  This algorithm (and
 * the implementation) allow for user-configurable variance of the environment data.
 * <p>
 * The environment data associated with this implementation is drawn from the JRE system property set, the machine
 * network settings, and the OS filesystem.  In this implementation, there is no tolerance for variance in the
 * environment.  If any of the measured values change, the persisted {@link SecretShareData} will need to be
 * regenerated.
 */
public class SecretShareDataSample implements SecretShareData {

    /**
     * Extract data from the process environment to use in the generation / recovery of the environment secret.
     *
     * @return a {@link Properties} object containing the raw environment values to use
     * @throws IonicException on failure to query the environment for the values to be used
     */
    @Override
    public Properties getData() throws IonicException {
        final Properties environment = new Properties();
        // user environment
        environment.setProperty("user.name", Environment.sysProp("user.name", null));
        // runtime environment
        environment.setProperty("java.version", Environment.sysProp("java.version", null));
        environment.setProperty("os.name", Environment.sysProp("os.name", null));
        environment.setProperty("os.version", Environment.sysProp("os.version", null));
        environment.setProperty("os.arch", Environment.sysProp("os.arch", null));
        // network environment
        environment.setProperty("hostname", Environment.hostname(null));
        environment.setProperty(Network.class.getName(),
                Value.joinArray(IDC.Message.DELIMITER, Network.getMacAddresses()));
        // filesystem environment
        final File folderBin = new File(System.getProperty("catalina.home"), "bin");
        final File folderLib = new File(System.getProperty("catalina.home"), "lib");
        environment.setProperty("timestamp-bin", Environment.dirEntryTime(folderBin.getPath(), null));
        environment.setProperty("content-lib", Environment.folderContent(folderLib.getPath(), ".*\\.jar", null));
        final File fileBat = new File(System.getProperty("catalina.home"), "bin/catalina.bat");
        environment.setProperty("hash-bat", Environment.fileContentHash(fileBat.getPath(), null));
        return environment;
    }

    /**
     * Request the definition of how the gathered data should be used to generate / recover the cryptography secret.
     * <p>
     * In this implementation, four "buckets" are used to group the raw environment values:
     * <ol>
     * <li>user values</li>
     * <li>Java runtime values</li>
     * <li>network values</li>
     * <li>filesystem values</li>
     * </ol>
     * <p>
     * The buckets are each configured to allow no variance in the values.  If any collected data changes from one
     * invocation to the next, the persisted {@link SecretShareData} will need to be regenerated.
     *
     * @return a collection of objects defining property keys to be used, and data recovery thresholds for each group
     */
    @Override
    public Collection<SecretShareBucket> getBuckets() {
        final Collection<String> keysUser = Collections.singletonList(
                "user.name");
        final Collection<String> keysRuntime = Arrays.asList(
                "java.version", "os.name", "os.version", "os.arch");
        final Collection<String> keysNetwork = Arrays.asList(
                "hostname", Network.class.getName());
        final Collection<String> keysFileSystem = Arrays.asList(
                "timestamp-bin", "content-lib", "hash-bat");
        return Arrays.asList(
                new SecretShareBucket(keysUser, keysUser.size()),
                new SecretShareBucket(keysRuntime, keysRuntime.size()),
                new SecretShareBucket(keysNetwork, keysNetwork.size()),
                new SecretShareBucket(keysFileSystem, keysFileSystem.size()));
    }
}
