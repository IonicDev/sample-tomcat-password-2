# Ionic Java SDK Sample Application / Tomcat SSL Keystore Password / SecretShare

The [Ionic SDK](https://dev.ionic.com/) provides an easy-to-use interface to the
[Ionic Platform](https://www.ionic.com/). In particular, the Ionic SDK exposes functions to perform Key Management
and Data Encryption.

The [Apache Tomcat](http://tomcat.apache.org/) web container application includes support for TLS (SSL) client 
connections on one or more dedicated ports.  To enable this feature, it is necessary to specify a 
[TLS keystore](https://en.wikipedia.org/wiki/Java_Secure_Socket_Extension) for each TLS port.  Keystores are typically 
password-protected for security reasons; the keystore section of the Tomcat configuration usually includes this 
password.

When possible, it is desirable to secure this password, to prevent its disclosure in the event of system 
compromise.  There are a few general-purpose strategies for providing passwords to applications at startup:

- Password is entered by hand in the process console at startup.
- Application configuration files contain password; files are secured via operating system file permissions.

In the first case, manual intervention prevents the ability to automate process restarts.  In the second case, 
exploitation of operating system vulnerabilities can expose the content of secured files.

The Ionic platform can be used in situations like this to provide an additional layer of protection to passwords in 
configuration files.  [Ionic chunk ciphers](https://dev.ionic.com/sdk/formats/chunk) can transform a passphrase to its 
encrypted representation, which can then be stored in the configuration 
file.  [Ionic policy controls](https://dev.ionic.com/api/policies) can then allow the release of the encryption key 
only to the device authorized to access the encrypted data.

A [previous SDK sample](https://github.com/IonicDev/sample-tomcat-password-1) walked through a use case in which the 
password 
was protected with Ionic encryption.  The chunk cipher encrypted representation of the password was stored in the 
Tomcat configuration file.  The *PropertySource* Tomcat extension was used to pass the plaintext password to Tomcat on 
startup, when the configuration is read.  The *PropertySource* also provides a mechanism for encryption of the original 
text.


## ProfilePersistor

Access to the Ionic platform is authorized by means of a serialized Ionic Secure Enrollment Profile (SEP).  This file
contains data defining the Ionic server to use, as well as data to identify the client making the requests.  (More 
details can be found [here](https://dev.ionic.com/platform/enrollment).)  In the previous SDK sample, this file 
contained plaintext JSON data.  An unauthorized user might also use this data in order to obtain the AES key protecting
the password.

There are multiple strategies that can be employed to mitigate this risk.

- The Ionic policy in force for the tenant might restrict access to the key by IP address, or by any other attribute 
available in the Ionic client key request.
- The Secure Enrollment Profile might be protected on serialization using one of the alternate persistence 
implementations.

The [Ionic SDK](https://github.com/IonicDev/ionic-java-sdk) includes the
[*ProfilePersistor*](https://dev.ionic.com/sdk_docs/ionic_platform_sdk/java/version_2.5.0/com/ionic/sdk/device/profile/persistor/ProfilePersistor.html) 
interface definition.  Implementations of this interface describe methods of serializing the information associated 
with a Secure Enrollment Profile.  Several class implementations are included in the core Ionic SDK:

| Implementation | Description |
| --- | --- |
| [DeviceProfilePersistorPlainText](https://dev.ionic.com/sdk_docs/ionic_platform_sdk/java/version_2.5.0/com/ionic/sdk/device/profile/persistor/DeviceProfilePersistorPlainText.html) | serialized file is unprotected |
| [DeviceProfilePersistorAesGcm](https://dev.ionic.com/sdk_docs/ionic_platform_sdk/java/version_2.5.0/com/ionic/sdk/device/profile/persistor/DeviceProfilePersistorAesGcm.html) | serialized file is protected by AES key |
| [DeviceProfilePersistorPassword](https://dev.ionic.com/sdk_docs/ionic_platform_sdk/java/version_2.5.0/com/ionic/sdk/device/profile/persistor/DeviceProfilePersistorPassword.html) | serialized file is protected by password |
| [DeviceProfilePersistorSecretShare](https://dev.ionic.com/sdk_docs/ionic_platform_sdk/java/version_2.5.0/com/ionic/sdk/device/profile/persistor/DeviceProfilePersistorSecretShare.html) | serialized file is protected by process environment |
  
While *DeviceProfilePersistorAesGcm* and *DeviceProfilePersistorPassword* both are encrypted on disk, the key / 
password must be supplied to the reader class on initialization.  Using these classes, the problem of plaintext 
password storage has not been eliminated, but rather a level of indirection has been added.


## DeviceProfilePersistorSecretShare

The *DeviceProfilePersistorSecretShare* implementation addresses this problem in an interesting way.  Rather than 
using an AES key directly (or deriving one from a password using a 
[Password-Based Key Derivation Function](https://en.wikipedia.org/wiki/PBKDF2)), *DeviceProfilePersistorSecretShare* 
allows the developer to define environment data that will be used to fabricate an AES key.  The data can be any 
information that is available to the Java process.  This might include (but is not limited to):

- the Java Runtime Environment [system property set](https://docs.oracle.com/javase/7/docs/api/java/lang/System.html#getProperties()),
- the [process environment](https://docs.oracle.com/javase/7/docs/api/java/lang/System.html#getenv()),
- the OS [host name](https://docs.oracle.com/javase/7/docs/api/java/net/InetAddress.html#getLocalHost()),
- the OS [network interfaces](https://docs.oracle.com/javase/7/docs/api/java/net/NetworkInterface.html#getNetworkInterfaces()),
- information about files and folders on the OS [filesystem](https://docs.oracle.com/javase/7/docs/api/java/io/File.html).

The Ionic SDK class 
[*Environment*](https://dev.ionic.com/sdk_docs/ionic_platform_sdk/java/version_2.5.0/com/ionic/sdk/crypto/env/Environment.html) 
has examples of methods that can be used to collect this information.  This information is passed to the 
*ProfilePersistor* by means of a custom 
[*SecretShareData*](https://dev.ionic.com/sdk_docs/ionic_platform_sdk/java/version_2.5.0/com/ionic/sdk/crypto/secretshare/SecretShareData.html) 
implementation.
  
In this sample application, the interface is implemented as 
[*SecretShareDataSample*](./src/main/java/com/ionic/sdk/addon/tomcat/ionic/SecretShareDataSample.java). 
This class defines several data "buckets" that are used to group data elements logically.  A *SecretShareData* 
implementation can have an arbitrary number of these logical data buckets.  

The class 
[*SecretShareGenerator*](https://dev.ionic.com/sdk_docs/ionic_platform_sdk/java/version_2.5.0/com/ionic/sdk/crypto/secretshare/SecretShareGenerator.html) 
contains the algorithm to fold the collected environment data together into an AES 
key.  The elements of each data bucket are first folded together into a derived 256-bit value.  The bucket values are 
then XORed together to fabricate the final value, which is cast to an AES key.  The associated data is persisted to a 
sibling file of the SecretShare SEP file.

When the SecretShare implementation is first run, the *SecretShareData* information is collected and used in 
*SecretShareGenerator* to create the encryption key.  This key is then used to protect the profile information.  The 
protected SEP and supplementary data are then serialized into filesystem files.  On subsequent runs, the environment 
data is collected, and used with the serialized supplementary data to reconstitute the encryption key.  This key is 
then used to read the SEP.

The *SecretShareDataSample* implementation requires that every piece of collected information be identical to that 
collected at the time of the first run.  If any piece of relevant data changes from its original value, a different AES 
key will be recovered, and decryption of the encrypted SEP file will fail.  However, the underlying SDK algorithm 
(based on [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)) allows for variation in 
the number of original data elements that must be recovered in order to reconstruct the original key.


## Tomcat Configuration *PropertySource*
The Tomcat software includes an extension point that allows users to modify the default loading of configuration 
variables.  The extension point is documented [here](https://tomcat.apache.org/tomcat-9.0-doc/config/systemprops.html).

This code sample will make use of the Tomcat extension point to allow for storage of arbitrary Ionic-protected 
configuration values in the Tomcat configuration.  These settings will be seamlessly decrypted on access by the Ionic 
configuration accessor.  The code sample will describe how this facility can be used to protect the Tomcat TLS keystore 
password.

The code sample will be run multiple times.  In the first run, the original Secure Enrollment Profile will be converted 
from plaintext to ciphertext protected by a key derived from the process environment.  The Tomcat configuration 
containing the plaintext keystore password will also be read, and the encrypted value will be written to the console.

In subsequent runs, the file containing the protected Secure Enrollment Profile will be loaded, and used to decrypt the 
encrypted password for use by Tomcat.


## Prerequisites

- physical machine (or virtual machine) with the following software installed
  - Java Runtime Environment 7+
  - Apache Maven (Java software project management tool)
- a valid, password-protected PKCS12 or JKS keystore
- a valid [Ionic Secure Enrollment Profile](https://dev.ionic.com/getting-started/create-ionic-profile) (a plaintext
json file containing access token data), in a file named *ionic.sep.plaintext.json*

The Ionic Secure Enrollment Profile contains data defining the Ionic server to use, as well as data to identify the 
client making the requests.  More details can be found [here](https://dev.ionic.com/platform/enrollment).

The instructions for obtaining an 
[Ionic Secure Enrollment Profile](https://dev.ionic.com/getting-started/create-ionic-profile) describe the 
`ionic-profiles` command line tool that is used for this purpose (given an active Ionic account).  Consult the web 
documentation for all of the options available in this tool.

During the walk-through of this demo, you will download the following:
- version 9.0.19 of Apache Tomcat (Java web container application)
- the git repository associated with this sample application


## Project Content

Let's take a brief tour of the content of this demo project.

**[javasdk-sample-tomcat/pom.xml]**

Here we declare the dependencies for the project.
```
    <dependency>
        <groupId>com.ionic</groupId>
        <artifactId>ionic-sdk</artifactId>
        <version>2.5.0</version>
    </dependency>
    <dependency>
        <groupId>org.apache.tomcat</groupId>
        <artifactId>tomcat-util</artifactId>
        <version>9.0.19</version>
    </dependency>
```

**[javasdk-sample-tomcat/src/main/java/com/ionic/sdk/addon/tomcat/util/PropertySourceSecretShare.java]**

This class extends the Tomcat interface 
[PropertySource](https://tomcat.apache.org/tomcat-9.0-doc/api/org/apache/tomcat/util/IntrospectionUtils.PropertySource.html).  Tomcat 
provides this interface to allow the interpretation of values in its configuration via extension code.  Running the 
Maven script will produce a Java JAR library that will be incorporated into a Tomcat installation.  When Tomcat is 
started, code in this class will be executed by Tomcat each time `${parameter}` denoted parameters are 
encountered in its configuration.  This class 
analyzes each value to determine whether it is Ionic-protected.  Any protected values will be decrypted in memory, and 
the plaintext values will be passed along to the application.

This class can also be used to generate the Ionic-protected ciphertext for the value.  To do this, set the value like 
this: `${IonicEncrypt.mysslkeystorepassword}`.  On Tomcat startup, when this configuration value is read, the 
*PropertySource* implementation will log the Ionic-protected representation of `mysslkeystorepassword`, and then 
pass `mysslkeystorepassword` back to Tomcat to be used.

The *PropertySourceSecretShare* constructor contains code to convert a plaintext SEP file into the equivalent 
*DeviceProfilePersistorSecretShare* file format.  When this code is triggered by the first Tomcat startup, it will find 
a plaintext SEP file, but no equivalent SecretShare file.  Under these conditions, the *SecretShareData* will be 
populated as defined in the class implementation.  The Secure Enrollment Profile and the associated share data will be 
written to the filesystem.  The plaintext SEP file will be left untouched, but it will not be used.

**[javasdk-sample-tomcat/src/main/java/com/ionic/sdk/addon/tomcat/ionic/SecretShareDataSample.java]**

This class implements the Ionic SDK interface *SecretShareData*.  It defines the data used to fabricate a secret from 
the process environment, as well as how this data is to be collected.  The data elements may be grouped as desired, and 
thresholds may be defined that dictate the number of data elements which must be recovered in order to reconstitute the 
group secret.  The group secrets are then combined to create the *SecretShareData* secret.

In this implementation, the specified data includes Java system properties, the host name, the network interfaces 
available to the JRE, and information collected from the Tomcat filesystem.  All data elements are defined to be 
significant, and any values that change after initial collection will cause recovery of the original secret to fail.

**[javasdk-sample-tomcat/src/main/java/com/ionic/sdk/addon/tomcat/ionic/ProfilePersistorUtil.java]**

This class contains two utility functions that glue the SecretShare capabilities together with the Tomcat 
*PropertySource* implementation.  The first function, `convertFromPlaintext()`, converts a plaintext Secure 
Enrollment Profile into an equivalent SecretShare representation.  This function only runs the first time Tomcat is 
started, when the plaintext SEP file is found, but the SecretShare SEP file is not found.  The second function, 
`getPersistorSecretShare()`, initializes the existing SecretShare SEP file reader for use by the Ionic SDK.


## Sample Application Walk-through

1. Clone git demo repository into an empty folder on your filesystem.
    ```shell
    git clone https://github.com/IonicDev/sample-tomcat-password-2.git
    ```

1. Navigate to the root folder of the *sample-tomcat-password-2* repository.  Run the following command to assemble the
demo webapp:
    ```shell
    mvn clean package
    ```

1. Download the [Tomcat image](https://tomcat.apache.org/download-90.cgi).

1. Inflate image into an empty folder on your filesystem.

1. Copy your password-protected PKCS12 or JKS keystore into the folder **[tomcat/conf]**.

1. Edit the file **[tomcat/conf/server.xml]**.  Find the (commented out) configuration section containing the 
declaration for SSL on port 8443.
    ```xml
    <!--
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true">
        <SSLHostConfig>
            <Certificate certificateKeystoreFile="conf/localhost-rsa.jks"
                         type="RSA" />
        </SSLHostConfig>
    </Connector>
    -->
    ```

    Uncomment and populate this configuration section following the example below.  Replace the value 
    `mysslkeystorepassword` with your actual password.
    ```xml
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
        maxThreads="150" SSLEnabled="true"
        scheme="https" secure="true" keystoreFile="conf/server.pkcs12" sslProtocol="TLS"
        keystorePass="${IonicEncrypt.mysslkeystorepassword}"
        />
    ```

    The `keystoreFile` attribute should reference the name of your keystore (for example: 'server.pkcs12').
    The value of the attribute `keystorePass` should be wrapped with the characters 
    **`${`** at the beginning and 
    **`}`** at the end.  These are interpreted by Tomcat as an instruction to resolve the wrapped content, thus 
    triggering the *PropertySourceSecretShare* sample code.

    When Tomcat encounters the value `${IonicEncrypt.mysslkeystorepassword}`, it will unwrap the data and pass the
    value `IonicEncrypt.mysslkeystorepassword` along to the custom *PropertySource*.  This code interprets any 
    value beginning with `IonicEncrypt.` as an instruction to encrypt the rest of the value, and log the 
    result.  The value `mysslkeystorepassword` will be passed back to Tomcat, allowing the keystore to be unlocked.

1. Add the file containing your Ionic Secure Enrollment Profile text into the *conf* folder of the new Tomcat image 
**[tomcat/conf/ionic.sep.plaintext.json]**.

1. Copy the code sample library file **[javasdk-sample-tomcat/target/ionic-sdk-tomcat-property-ss-0.0.1.jar]** 
into **[tomcat/lib]**.

1. Copy all files in **[javasdk-sample-tomcat/target/lib]** into **[tomcat/lib]**.  There should be two files:
    - ionic-sdk-2.5.0.jar
    - javax.json-1.0.4.jar

1. Edit **[tomcat/bin/catalina.bat]**.  Find the script code at the label **`:doRun`**.  Insert a line defining the 
property that enables the Ionic sample *PropertySource*.
    
    before:
    ```script
    :doRun
    shift
    if not ""%1"" == ""-security"" goto execCmd
    shift
    echo Using Security Manager
    set "SECURITY_POLICY_FILE=%CATALINA_BASE%\conf\catalina.policy"
    goto execCmd
    ```

    after:
    ```script
    :doRun
    shift
    set CATALINA_OPTS=-Dorg.apache.tomcat.util.digester.PROPERTY_SOURCE=com.ionic.sdk.addon.tomcat.util.PropertySourceSecretShare
    if not ""%1"" == ""-security"" goto execCmd
    shift
    echo Using Security Manager
    set "SECURITY_POLICY_FILE=%CATALINA_BASE%\conf\catalina.policy"
    goto execCmd
    ```

1. Navigate to the root folder of the Tomcat instance.  Run the following command in a console to start Tomcat 
    (Ctrl+C to stop):
    ```shell
    bin\catalina.bat run
    ```
    
    If the SSL keystore password was correct, the server should start normally.  

1. Enter the (Ctrl+C) key sequence to stop the Tomcat process.

1. Examine the Tomcat folder **[tomcat/conf/]**.  Verify that two new files have been created:
   - **[tomcat/conf/ionic.sep.secretshare.json]**
   - **[tomcat/conf/ionic.secret.secretshare.json]**

1. Examine the console output for the Tomcat startup.  You should find a line like the following:
    ```text
    INFO [main] com.ionic.sdk.addon.tomcat.util.PropertySource.getProperty IonicEncrypt. = ~!3!D7GHDudu-Z8!B+RTDJLPjs/ICOqlx44P6gwnnfnsuuwtzHwVn+cgIi4ABgdg!
    ```

    The portion of the line after `IonicEncrypt. = ` is the Ionic chunk cipher representation of the keystore 
    password.

1. Edit the file **[tomcat/conf/server.xml]** again.  Find the configuration section containing the 
declaration for SSL on port 8443.

    Modify the content, replacing the value 
    `${IonicEncrypt.mysslkeystorepassword}` with the chunk cipher representation of the password.
    ```xml
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
        maxThreads="150" SSLEnabled="true"
        scheme="https" secure="true" keystoreFile="conf/server.pkcs12" sslProtocol="TLS"
        keystorePass="${~!3!D7GHDudu-Z8!B+RTDJLPjs/ICOqlx44P6gwnnfnsuuwtzHwVn+cgIi4ABgdg!}"
        />
    ```
    Don't forget to wrap the chunk cipher value with the characters 
    **`${`** at the beginning and 
    **`}`** at the end.  

1. Run the following command in a console to start Tomcat again:
    ```shell
    bin\catalina.bat run
    ```
    
    The server should start normally, unlocking the SSL keystore with the Ionic decrypted password.


## Analysis

While the file **[tomcat/conf/ionic.sep.plaintext.json]** is still present on the filesystem, it is only used when 
needed to generate the SecretShare SEP.  You can verify this by removing it from the Tomcat *conf* folder.  (Move it 
to a safe place on your filesystem in case you need it later.)  Tomcat (with the Ionic-protected keystore password) 
should start normally.

Part of the data used to generate the SEP secret is the list of JAR files contained in the folder 
**[tomcat/lib/]**.  Any addition or removal of a JAR into this folder will cause Tomcat startup to fail, as the Secure 
Enrollment Profile will be unrecoverable.  To verify this, navigate to the **[tomcat/lib/]** folder using an OS 
explorer window.  Paste a copy of **[tomcat/lib/catalina.jar]** into this folder.  Tomcat will fail to start, as the 
Ionic *PropertySource* extension will not initialize.  If the copy is removed, Tomcat should start normally.

If you want to regenerate the *SecretShareData* SEP (for example, to account for changes to the Tomcat environment), 
the procedure is straightforward.

1. Delete the files **[tomcat/conf/ionic.sep.secretshare.json]** and **[tomcat/conf/ionic.secret.secretshare.json]**.
1. Ensure that the file **[tomcat/conf/ionic.sep.plaintext.json]** is in place.
1. Start the Tomcat web server.

The two deleted files will be regenerated from the plaintext SEP data and saved.

Arbitrarily complex data may be incorporated into a custom implementation of *SecretShareData*, in order to raise the 
bar guarding against unwanted exposure of the SEP data.  It is recommended to use low latency queries to generate the 
data, to minimize the amount of time needed to reconstitute the SEP secret.


## Conclusion

In this sample, the Tomcat *PropertySource* facility was used to protect the SSL keystore password in the configuration 
with Ionic encryption.  Ionic server policy may be used to restrict access to the decryption key.

Additionally, the Ionic Secure Enrollment Profile (SEP) used by Tomcat is protected by an encryption key derived from 
the process environment.  An unauthorized user would need access to every piece of data defined in the 
*SecretShareData* implementation in order to recover the SEP data.  Without a valid SEP, the encryption 
key protecting the keystore password is inaccessible. 

Other software applications have similar facilities to guard sensitive content in configuration files.  For example, 
the Apache HTTPD web server uses the `SSLPassPhraseDialog` facility, described 
[here](https://httpd.apache.org/docs/2.4/ssl/ssl_faq.html#removepassphrase).

Ionic's platform is powerful and flexible enough to be broadly applicable to the data protection needs of modern
organizations.
