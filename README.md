<h1>HELIOS Security and Privacy API</h1>

<h2>Introduction</h2>

Security and Privacy API provides cryptographic services to HELIOS
components.<p>

HELIOS Security and Privacy API is one of the HELIOS Core APIs as
highlighted in the picture below:<p>

<img src="https://raw.githubusercontent.com/helios-h2020/h.core-SecurityAndPrivacyManager/master/doc/images/helios-security.png"
alt="HELIOS Security and Privacy API"/>

<h2>API usage</h2>

See javadocs in zip file 
<a href="https://raw.githubusercontent.com/helios-h2020/h.core-SecurityAndPrivacyManager/master/doc/javadocs.zip">[javadocs.zip]</a>.

<h2>Android Studio project structure</h2>

This Android Studio 3.5 project contains the following components:
<ul>
	<li>app - Security and Privacy API test application</li>
	<li>doc - Additional documentation files</li>
	<li>lib - Security and Privacy API implementation</li>
</ul>

<h2>Internal usage of APIs</h2>

Detailed examples for using internal structures of the Security module are given below.

<h3>SIGN IN</h3>

User's RSA keys are generated at sign in:

<pre><code>	KeyPair signingKeyPair = generateRSAKeyPair();
	KeyPair encryptinKeyPair = generateRSAKeyPair();
</code></pre>

Secret keys are stored to the key store with the <code>string</code> masterPassword that the user chose at sign in:

<pre><code>	void storePrivateKey(signingKeyPair.getPrivate(), "USER SIGNING KEY", masterPassword);
	void storePrivateKey(encryptingKeyPair.getPrivate(), "USER DECRYPTING KEY", masterPassword);
</code></pre>

Later the private keys can be retrieved with the masterPassword:

<pre><code>	PrivateKey signingKey=retrievePrivateKey("USER SIGNING KEY", masterPassword);
	PrivateKey decryptingKey=retrievePrivateKey("USER DECRYPTING KEY", masterPassword);
</code></pre>

Public keys are stored in a <code>byte[]</code> userData that includes
<ul>
	<li>User info: name, userid, address etc.</li>
	<li>Public signature verification key: <code>signingKeyPair.getPublic();</code></li>
	<li>Public encrypting key: <code>encryptingKeyPair.getPublic();</code></li>
</ul>

This userData is signed using the private signing key:

<pre><code>	byte[] userDataSignature = signBytes(signingKeyPair.getPrivate(), userData);
</code></pre>

userData together with userDataSignature is stored at the device and sent to all alters at request.<p>

For tutorial about converting RSA keys to byte array and back see:
<a href="http://www.java2s.com/Tutorial/Java/0490__Security/Thebytescanbeconvertedbacktopublicandprivatekeyobjects.htm">KeyPairGenerator « Security « Java Tutorial</a><p>

Our RSA keys are created with definitions

<pre><code>	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	keyGen.initialize(2048);
</code></pre>


<h3>STORING ALTERS' KEYS</h3>


The userData of the receiver is needed when sending encrypted messages to alters.
The userData of the sender is needed when verifying the signature of the sender.<p>

When the userData and userDataSignature of an alter (alterData and alterDataSignature) is received, the signature is checked before they are stored on the device:

<pre><code>	boolean verifyBytes(alterSignatureVerificationKey, alterData, alterDataSignature);
</code></pre>

Here alterSignatureVerificationKey is the public signature verification key from alterData.

<h3>SENDING A MESSAGE</h3>

When a byte[] message is sent to an alter with public encryption verification key alterEncryptingKey, first a new AES key is generated:

<pre><code>	SecretKey messageKey = generateAESKey();
</code></pre>
	
The message is encrypted using this key:

<pre><code>	byte[] encryptedMessage = encryptBytes(message, messageKey, iv);
</code></pre>
	
Encryption creates an initial value iv of 12 bytes. 
The encryptedMessage is signed using the sender's private signing key:

<pre><code>	byte[] messageSignature = signBytes(signingKey, encryptedMessage);
</code></pre>
	
The messageKey is encrypted using the receiver's public encrypting key:

<pre><code>	byte[] encryptedMessageKey = encryptAESKey(alterEncryptingKey, messageKey);
</code></pre>

The following items are sent to the receiver: encryptedMessage, iv, encryptedMessageKey, messageSignature.
Here we assume that message includes the metadata: date, time, sender, receiver, message ID, etc.
The messageKey can be put into key storage:

<pre><code>	void storeSecretKey(messageKey, alias, password);
</code></pre>
	
Where string alias is a name that describes the use of the messageKey and <code>string</code> password is some chosen phrase that is needed later when retrieving the messageKey:

<pre><code>	SecretKey messageKey = retrieveSecretKey(alias, password);
</code></pre>

The messageKey can be used later when sending a new message to the same receiver. 
Then the encryptedMessageKey need not be sent to the receiver again if the receiver has also stored the messageKey.

<h3>RECEIVING A MESSAGE</h3>

When encryptedMessage, iv, encryptedMessageKey and messageSignature are received and the sender's public signature verification key alterSignatureVerificationKey is known,
first the validity of the signature is checked:

<pre><code>	boolean verifyBytes(alterSignatureVerificationKey, encryptedMessage, messageSignature);
</code></pre>
	
If true, then the messageKey is decrypted:

<pre><code>	SecretKey messageKey = decryptAESKey(decryptingKey, encryptedMessageKey);
</code></pre>
	
Then the encryptedMessage is decrypted using this key and iv:

<pre><code>	byte[] message = decryptBytes(encryptedMessage, messageKey, iv);
</code></pre>
	
<h3>STORING A MESSAGE</h3>

Instead of sending encryptedMessage, iv, encryptedMessageKey and messageSignature to the receiver they could be placed in a storage where the receiver has access to them.
If there are several receivers, the messageKey could be separately encrypted with the public encrypting keys of all of them.
Then all different encryptions of the messageKey are placed in the storage. 


<h3>ACCESS CONTROL</h3>

<b><pre><code>	void setAccessRules(String fileId, HeliosAccessControlRulesTable rulesTable)
</code></pre></b>

This method sets the access rules for file/resource called <code>fileId</code>.
Rules table lists actions that are allowed for users with some userID or attribute.<p>

An example of rule table:

<pre><code>	HeliosAccessControlRulesTable table = new HeliosAccessControlRulesTable();
	table.add("read", ALLOWED, "Bob", USERID);
	table.add("read", ALLOWED, "Frank", USERID);
	setAccessRules("myfile", table);
</code></pre>

This gives read access for users Bob and Frank for file myfile.
If the table is <code>null</code> then all rules for the fileId are removed.

<b><pre><code>	HeliosAccessControlRulesTable getAccessRules(String fileId)
</code></pre></b>

This method returns the rules that were set for file/resource fileId using the <code>setAccessRules</code> method. 

An example:

<pre><code>	HeliosAccessControlRulesTable table = mgr.getAccessRules("myfile");
	table.remove("read", ALLOWED,"Bob", USERID);
	table.add("write", DENIED,"Frank", USERID);
	setAccessRules("myfile", table);
</code></pre>

This removes the rule that Bob is allowed to read the file myfile and adds a rule that Frank is not allowed to write to file myfile.

<b><pre><code>	boolean requestAccess(String fileId, String action, String userId)
</code></pre></b>

This method checks if user with userId has access to perform action on file/resource fileId.
The method returns false if there is no rule to allow the action for the user or there is a rule that denies the action for the user.<p>

The contextual ego network is queried to find all attributes that the user userId has if they are needed to make the decision.
At the moment there is only a toy example of hard coded attributes for and all users have attribute "testattribute".<p>

The right to read for all users that have testattribute can be added as follows:

<pre><code>	table.add("read", ALLOWED, "testattribute", EGONETWORKATTRIBUTE);
</code></pre>
	
TODO:<p>

Adding interaction with ContextualEgoNetwork to find out at lest in what contexts the userID is a friend of the Ego.
