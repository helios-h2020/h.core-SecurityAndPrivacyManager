# HELIOS Security and Privacy API #

## Introduction ##

Security and Privacy API provides cryptograhic services to HELIOS
components.

HELIOS Security and Privacy API is one of the HELIOS Core APIs as
highlighted in the picture below:

![HELIOS Security and Privacy API](doc/images/helios-security.png "Security and Privacy API")

## API usage ##

More detailed examples for using internal structures of the Security module. 

See javadocs in zip file [javadocs.zip](doc/javadocs.zip).


## Android Studio project structure ##

This Android Studio 3.5 project contains the following components:

* app - Security and Privacy API test application

* doc - Additional documentation files

* lib - Security and Privacy API implementation


## Internal usage of APIs ##

More detailed examples for using internal structures of the Security module are given below.


```
SIGN IN
-------

User's RSA keys are generated at sign in:

	KeyPair signingKeyPair = generateRSAKeyPair();
	KeyPair encryptinKeyPair = generateRSAKeyPair();

Secret keys are stored to the key store with the string masterPassword that the user chose at sign in:

	void storePrivateKey(signingKeyPair.getPrivate(), "USER SIGNING KEY", masterPassword);
	void storePrivateKey(encryptingKeyPair.getPrivate(), "USER DECRYPTING KEY", masterPassword);

Later the private keys can be retrieved with the masterPassword:

	PrivateKey signingKey=retrievePrivateKey("USER SIGNING KEY", masterPassword);
	PrivateKey decryptingKey=retrievePrivateKey("USER DECRYPTING KEY", masterPassword);

Public keys are stored in a byte[] userData that includes
	* User info: name, userid, address etc.
	* Public signature verification key: signingKeyPair.getPublic();
	* Public encrypting key: encryptingKeyPair.getPublic();

This userData is signed using the private signing key:

	byte[] userDataSignature = signBytes(signingKeyPair.getPrivate(), userData);

userData together with userDataSignature is stored at the device and sent to all alters at request.

For tutorial about converting RSA keys to byte array and back see:
	http://www.java2s.com/Tutorial/Java/0490__Security/Thebytescanbeconvertedbacktopublicandprivatekeyobjects.htm
Our RSA keys are created with definitions
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);


STORING ALTERS' KEYS
--------------------

The userData of the receiver is needed when sending encrypted messages to alters.
The userData of the sender is needed when verifying the signature of the sender.

When the userData and userDataSignature of an alter (alterData and alterDataSignature) is received, the signature is checked before they are stored on the device:

	boolean verifyBytes(alterSignatureVerificationKey, alterData, alterDataSignature);
	
Here alterSignatureVerificationKey is the public signature verification key from alterData.


SENDING A MESSAGE
-----------------

When a byte[] message is sent to an alter with public encryption verification key alterEncryptingKey, first a new AES key is generated:

	SecretKey messageKey = generateAESKey();
	
The message is encrypted using this key:

	byte[] encryptedMessage = encryptBytes(message, messageKey, iv);
	
Encryption creates an initial value iv of 12 bytes. 
The encryptedMessage is signed using the sender's private signing key:

	byte[] messageSignature = signBytes(signingKey, encryptedMessage);
	
The messageKey is encrypted using the receiver's public encrypting key:

	byte[] encryptedMessageKey = encryptAESKey(alterEncryptingKey, messageKey);

The following items are sent to the receiver: encryptedMessage, iv, encryptedMessageKey, messageSignature.
Here we assume that message includes the metadata: date, time, sender, receiver, message ID, etc.
The messageKey can be put into key storage:

	void storeSecretKey(messageKey, alias, password);
	
Where string alias is a name that describes the use of the messageKey and string password is some chosen phrase that is needed later when retrieving the messageKey:

	SecretKey messageKey = retrieveSecretKey(alias, password);

The messageKey can be used later when sending a new message to the same receiver. 
Then the encryptedMessageKey need not be sent to the receiver again if the receiver has also stored the messageKey.


RECEIVING A MESSAGE
-------------------

When encryptedMessage, iv, encryptedMessageKey and messageSignature are received and the sender's public signature verification key alterSignatureVerificationKey is known,
first the validity of the signature is checked:

	boolean verifyBytes(alterSignatureVerificationKey, encryptedMessage, messageSignature);
	
If true, then the messageKey is decrypted:

	SecretKey messageKey = decryptAESKey(decryptingKey, encryptedMessageKey);
	
Then the encryptedMessage is decrypted using this key and iv:

	byte[] message = decryptBytes(encryptedMessage, messageKey, iv);

	
STORING A MESSAGE
-----------------

Instead of sending encryptedMessage, iv, encryptedMessageKey and messageSignature to the receiver they could be placed in a storage where the receiver has access to them.
If there are several receivers, the messageKey could be separately encrypted with the public encrypting keys of all of them.
Then all different encryptions of the messageKey are placed in the storage. 

```



