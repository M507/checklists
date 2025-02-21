
const checklistItems = [
    {
        name: "Improper Export of Android Application Components",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "The Android application exports a component for use by other applications but does not properly restrict which applications can launch the component or access the data it contains."
    },
    {
        name: "Hardcoded Sensitive Information in Application Code",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Sensitive information can be stored in code which can be used by an attacker to compromise the application."
    },
    {
        name: "Insecure Logging of the Application",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Android provides capabilities for an app to output logging sensitive information and obtain log output. Applications can send information to log output using the android.util.Log class. To obtain log output, applications can execute the logcat command."
    },
    {
        name: "SQL Injection via Projection in Content Provider",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Any application on the same device can read and write to the Content Provider which is exported. Usually, content providers use either SQLite databases or files as an underneath data storage with which they operate by determining which URIs does the provider deal with. An SQL injection attack consists of insertion of an SQL query via the input data from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system."
    },
    {
        name: "Application has Set Insecure Permissions",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Android is a privilege-separated operating system in which each application runs with a distinct system identity (Linux user ID and group ID). Parts of the system are also separated into distinct identities. Linux thereby isolates applications from each other and from the system. Additional finer-grained security features are provided through a 'permission' mechanism that enforces restrictions on a process's specific operations, and per-URI permissions for granting ad hoc access to specific pieces of data. It was observed that the application has set insecure permissions, which will create a security threat to the application."
    },
    {
        name: "Debuggable Flag is Set to True",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "If an application is flagged as debuggable, an attacker can inject his/her own code to execute it in the context of the vulnerable application process."
    },
    {
        name: "Information Leakage from Clipboard",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "The most interesting characteristic of Android Clipboard is its globally accessible nature, i.e., everything placed on the clipboard is public and accessible to all the running apps on the device without any permission requirements or user interactions. Android even allows apps to monitor data changes on the clipboard by registering a callback listener to the system. The risk is related to mechanism of copy & paste in Android system. The information which was copied by user or application, is once stored in the buffer called Clipboard. The information stored in Clipboard is distributed to other applications when it is pasted by a user or an application. So there is a risk which leads to information leakage in this Clipboard function. It is because the entity of Clipboard is single in a system and any application can obtain the information stored in Clipboard at any time by using ClipboardManager. It means that all the information which user copied/cut, is leaked out to the malicious application. In contrast, Android considers each app as a different user with different privilege. Due to the global unguarded access, various users, i.e., apps, can arbitrarily operate on Android Clipboard without any restriction."
    },
    {
        name: "Sensitive Details in Device Memory (If Debuggable Flag is True)",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "If application does flush out data from memory, the sensitive info like login credentials, mpin, passcodes, etc. gets stored in the device and an adversary can view sensitive info if he gets physical access to the victim's device."
    },
    {
        name: "Sensitive Data Disclosure in Recent Apps",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "The application exposes sensitive information via the recent application list in Android. In order to provide visual transitions in the interface, iOS has been proven to capture and store snapshots (screenshots or captures) as images stored in the file system portion of the device NAND flash. This occurs when a device suspends (rather than terminates), when either the home button is pressed, or a phone call or other event temporarily suspends the application. These images can often contain user and application data, and in one published case, contained the user’s credit card information, his property details, and his personal details."
    },
    {
        name: "Application is Vulnerable to Reverse Engineering Attack",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "A lack of binary protections within a mobile app exposes the application and its owner to a large variety of technical and business risks if the underlying application is insecure or exposes sensitive intellectual property. A lack of binary protections results in a mobile app that can be analyzed, reverse-engineered, and modified by an adversary in a rapid fashion. It was observed that the application source code can be accessed easily with the help of several tools. By this, an attacker can be able to access all packages inside the '.APK' file, which contains resource files, different bundles, package information and preference information."
    },
    {
        name: "Application Does Not Have Logout Functionality",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Session termination is an important part of the session lifecycle. Reducing to a minimum the lifetime of the session tokens decreases the likelihood of a successful session hijacking attack. There are multiple issues that can prevent the effective termination of a session. For the ideal secure web application, a user should be able to terminate at any time through the user interface. Every page should contain a log-out button in a place where it is directly visible. Unclear or ambiguous log-out functions could cause the user not to trust such functionality."
    },
    {
        name: "Insecure Data Storage in File System",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Insecure data storage vulnerabilities occur when development teams assume that users or malware will not have access to a mobile device's filesystem and subsequent sensitive information in data-stores on the device. Filesystems are easily accessible. Organizations should expect a malicious user or malware to inspect sensitive data stores. Rooting or jailbreaking a mobile device circumvents any encryption protections. When data is not protected properly, specialized tools are all that is needed to view application data."
    },
    {
        name: "Backup Flag is Set to True",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "The Android operating system offers a backup/restore mechanism for installed packages through the ADB utility. By default, full Backup of applications, including the private files stored in /data is performed, but this behavior can be customized by implementing a Backup Agent class. This way, applications can feed the backup process with custom files and data."
    },
    {
        name: "Application is Using WebView with JavaScript Enabled",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "WebView is a view that displays web pages. This class is the basis upon which you can roll your own web browser or simply display some online content within your Activity. It uses the WebKit rendering engine to display web pages and includes methods to navigate forward and backward through a history, zoom in and out, perform text searches and more."
    },
    {
        name: "Application is Vulnerable to Runtime Analysis and Manipulation",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Runtime analysis and manipulation means analyzing the flow of an app during its runtime. It would be really good to know what are the methods being called in a particular view controller or in a particular class."
    },
    {
        name: "Application Makes Use of Weak Cryptographic Algorithms",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Using a weak or broken algorithm ruins the protection granted by using cryptographic mechanisms in the first place, harming the confidentiality or integrity of sensitive user data. This could allow an attacker to steal secret information, alter sensitive data, or forge the source of modified messages. The application code specifies the name of the selected cryptographic algorithm, either via a String argument, a factory method, or a specific implementation class. These algorithms have fatal cryptographic weaknesses, that make it trivial to break in a reasonable timeframe. Strong algorithms should withstand attacks far beyond the realm of possible."
    },
    {
        name: "Application Works in Rooted Device",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "It was observed that the application has no check for installation on the rooted device."
    },
    {
        name: "SSL Pinning Not Implemented Properly/Not Implemented",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Pinning is the process of associating a host with their expected X509 certificate or public key. Once a certificate or public key is known or seen for a host, the certificate or public key is associated or pinned to the host."
    },
    {
        name: "Code Tampering Attack",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "It is possible to reverse engineer a mobile app using tools readily available in the market. An adversary can decompile an android app, make changes to the source & then re-compile & sign the same using his own key. Then this tampered app can be sent to the victim via third-party app stores or social engineering thus successfully accomplishing the attacker's goal such as capturing sensitive information of victims or mobile phone compromise thereby causing reputation and financial damage to the company."
    },
    {
        name: "User Authentication for Sensitive Data (Critical Application)",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Application shows sensitive information without authentication."
    },
    {
        name: "Cleartext Traffic is Set to True",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "The app intends to use cleartext network traffic, such as cleartext HTTP, FTP stacks, DownloadManager, and MediaPlayer. The default value for apps that target API level 27 or lower is 'true'. Apps that target API level 28 or higher default to 'false'. The key reason for avoiding cleartext traffic is the lack of confidentiality, authenticity, and protections against tampering."
    },
    {
        name: "printStackTrace() Function is Used in the Application",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "If the application shows the attacker a stack trace, it relinquishes information that makes the attacker's job significantly easier. For example, a stack trace might show the attacker a malformed SQL query string, the type of database used, and the version of the application container. This information enables the attacker to target known vulnerabilities in these components."
    },
    {
        name: "Application's Manifest File Reveals Sensitive Information",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Sensitive information like API keys stored in code can be used by an attacker to compromise the application."
    },
    {
        name: "Sensitive Data Shared with Third Party",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Sensitive data is being shared with third party services."
    },
    {
        name: "Application Runs on Older Platform",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Application runs on older version of android platform having publicly known vulnerabilities which attacker can leverage to compromise the device to steal sensitive information or to install malwares."
    },
    {
        name: "addJavaScriptInterface Enabled",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "Injects the supplied Java object into this WebView. The object is injected into all web page frames, including all the iframes, using the supplied name. This allows the Java object's methods to be accessed from JavaScript. For applications targeted to API level Build.VERSION_CODES.JELLY_BEAN_MR1 and above, only public methods annotated with JavascriptInterface can be accessed from JavaScript."
    },
    {
        name: "setAllowFileAccess Enabled",
        tags: ["Android", "Static"],
        comments: "",
        recommendations:"",
        description: "WebView file access is enabled by default. Since API 3 (Cupcake 1.5), the method setAllowFileAccess() is available for explicitly enabling or disabling it. A WebView with file access enabled will be able to access all the same files as the embedding application, such as the application sandbox (located in /data/data/<package_name>), /etc., /sdcard, among others. Above API 19(KitKat 4.4 - 4.4.4), the app will need the android.permission.READ_EXTERNAL_STORAGE permission."
    },
    {
        name: "Application is vulnerable to OS Command Injection Attack",
        description: "OS command injection is a technique used via a web interface in order to execute OS commands on a web server. The user supplies operating system commands through a web interface in order to execute OS commands. Any web interface that is not properly sanitized is subject to this exploit. With the ability to execute OS commands, the user can upload malicious programs or even obtain passwords.",
        tags: ["OS Command Injection", "Web Security","Android","Dynamic"],
        comments: "",
        recommendations:"Review and sanitize all user inputs."
    },
    {
        name: "Application is vulnerable to Remote Code Execution Attack",
        description: "Remote Code Execution is a vulnerability that can be exploited if user input is injected into a File or a String and executed by the programming language's parser. Usually this behavior is not intended by the developer of the web application. A Remote Code Evaluation can lead to a full compromise of the vulnerable web application and also web server.",
        tags: ["Remote Code Execution", "Critical","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure proper input validation and sanitation."
    },
    {
        name: "Application is vulnerable to Remote File Inclusion Attack",
        description: "Remote File Inclusion (RFI) is the process of including remote files through the exploiting of vulnerable inclusion procedures implemented in the application. This vulnerability occurs, for example, when a page receives, as input, the path to the file that has to be included and this input is not properly sanitized, allowing external URL to be injected and executed on server.",
        tags: ["Remote File Inclusion", "File Handling","Android","Dynamic"],
        comments: "",
        recommendations:"Validate and sanitize file paths rigorously."
    },
    {
        name: "Application is vulnerable to Cross-Site Scripting Attack",
        description: "Cross-site Scripting (XSS) is a client-side code injection attack. The attacker aims to execute malicious scripts in a web browser of the victim by including malicious code in a legitimate web page or web application. The actual attack occurs when the victim visits the web page or web application that executes the malicious code.",
        tags: ["XSS", "Client-side","Android","Dynamic"],
        comments: "",
        recommendations:"Implement content security policies."
    },
    {
        name: "CSRF Token Not Implemented",
        description: "Cross-Site Request Forgery (CSRF) is an attack which forces an end user to execute unwanted actions on a web application in which he/she is currently authenticated. With a little help of social engineering (like sending a link via email/chat), an attacker may force the users of a web application to execute actions of the attacker's choice. A successful CSRF exploit can compromise end user data and operation in case of normal user. If the targeted end user is the administrator account, this can compromise the entire web application.",
        tags: ["CSRF", "Session Security","Android","Dynamic"],
        comments: "",
        recommendations:"Implement and enforce CSRF tokens in all forms."
    },
    {
        name: "Application is vulnerable to Directory Traversal Attack",
        description: "Any web application restricts its users from accessing data outside the site's root directory. This restriction can sometimes be overcome by a directory traversal attack. In this attack, the adversary uses a series of \"../\" to step out of the root folder and access other folders/files. Files like /etc/passwd in UNIX and the system files in Windows can be accessed by this attack.",
        tags: ["Directory Traversal", "Path Traversal","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure path traversal filtering is in place."
    },
    {
        name: "Application is vulnerable to HTML Injection Attack",
        description: "HTML injection attack only allows the injection of certain HTML tags. When an application does not properly handle user-supplied data, an attacker can supply valid HTML code, typically via a parameter value, and inject their own content into the page. This attack is typically used in conjunction with some form of social engineering, as the attack exploits a code-based vulnerability and a user's trust.",
        tags: ["HTML Injection", "Data Validation","Android","Dynamic"],
        comments: "",
        recommendations:"Sanitize all user inputs to prevent HTML injection."
    },
    {
        name: "Application is vulnerable to Iframe Injection Attack",
        description: "In an Iframe injection attack, the attacker exploits a specific cross-frame-scripting bug in a web browser to access private data on a third-party website. The attacker induces the browser user to navigate to a web page the attacker controls; the attacker's page loads a third-party page in an HTML frame; and then javascript executing in the attacker's page steals data from the third-party page.",
        tags: ["Iframe Injection", "XSS","Android","Dynamic"],
        comments: "",
        recommendations:"Validate and escape all external inputs and links."
    },
    {
        name: "Application is vulnerable to IMAP/SMTP Injection Attack",
        description: "An attacker exploits weaknesses in input validation on IMAP/SMTP servers to execute commands on the server. Web-mail servers often sit between the Internet and the IMAP or SMTP mail server. User requests are received by the web-mail servers which then query the back-end mail server for the requested information and return this response to the user. In an IMAP/SMTP command injection attack, mail-server commands are embedded in parts of the request sent to the web-mail server. If the web-mail server fails to adequately sanitize these requests, these commands are then sent to the back-end mail server where the commands are then executed.",
        tags: ["IMAP/SMTP Injection", "Command Injection", "Email Security","Android","Dynamic"],
        comments: "",
        recommendations:"Sanitize and validate all input fields that interact with mail servers."
    },
    {
        name: "Application is vulnerable to LDAP Injection Attack",
        description: "LDAP is an acronym for Lightweight Directory Access Protocol. LDAP injection is a server side attack, which could allow sensitive information about users and hosts represented in an LDAP structure to be disclosed, modified, or inserted. This is done by manipulating input parameters afterwards passed to internal search, add, and modify functions.",
        tags: ["LDAP Injection", "Directory Services","Android","Dynamic"],
        comments: "",
        recommendations:"Implement strict input validation and encoding strategies for handling LDAP queries."
    },
    {
        name: "Application is vulnerable to Link Injection Attack",
        description: "Link Injection is the act of modifying the content of a site by embedding in it a URL to an external site, or to a script in the vulnerable site. By launching these attacks from the vulnerable site itself, the attacker increases the chances of success, because the user is more likely to be logged in. The Link Injection vulnerability is a result of insufficient user input sanitation, which is later returned to the user in the site response.",
        tags: ["Link Injection", "URL Manipulation","Android","Dynamic"],
        comments: "",
        recommendations:"Enhance output encoding and input sanitization to prevent link injection."
    },
    {
        name: "Application is vulnerable to Log Injection Attack",
        description: "Applications typically use log files to store a history of events or transactions for later review, statistics gathering, or debugging. In Log Injection, an attacker will be able to create a forged entry in the application log which reduces the value of the logs, and frustrates any forensic type activities.",
        tags: ["Log Injection", "Data Integrity","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure proper sanitization and validation of all data written to log files."
    },
    {
        name: "Application is vulnerable to Price Manipulation Attack",
        description: "The application does not verify the amount which is to be paid by the user, allowing an adversary to modify the amount and complete a transaction for a lesser cost.",
        tags: ["Price Manipulation", "E-commerce Security","Android","Dynamic"],
        comments: "",
        recommendations:"Implement server-side validation of all transaction amounts and data."
    },
    {
        name: "Application is vulnerable to Privilege Escalation Attack",
        description: "Privilege escalation means a user receives privileges he is not ennamed to. These privileges can be used to delete files, view private information, or install unwanted programs, such as viruses. It usually occurs when a system has a bug that allows security to be bypassed or has flawed design assumptions about how it will be used.",
        tags: ["Privilege Escalation", "Authorization Flaws","Android","Dynamic"],
        comments: "",
        recommendations:"Regularly update and patch systems, and review permission settings."
    },
    {
        name: "Application is vulnerable to Session Hijacking",
        description: "The Session Hijacking attack consists of the exploitation of the web session control mechanism, which is normally managed for a session token. The Session Hijacking attack compromises the session token by stealing or predicting a valid session token to gain unauthorized access to the Web Server.",
        tags: ["Session Hijacking", "Session Management","Android","Dynamic"],
        comments: "",
        recommendations:"Implement robust session management and token handling mechanisms."
    },
    {
        name: "Application is vulnerable to SQL Injection Attack",
        description: "An SQL injection attack consists of insertion of an SQL query via the input data from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system.",
        tags: ["SQL Injection", "Database Security","Android","Dynamic"],
        comments: "",
        recommendations:"Use prepared statements and parameterized queries to handle SQL commands."
    },
    {
        name: "Application is vulnerable to SSI Injection Attack",
        description: "SSI Injection is a server-side exploit technique that allows an attacker to send code into a web application, which will later be executed locally by the web server.",
        tags: ["SSI Injection", "Server-Side","Android","Dynamic"],
        comments: "",
        recommendations:"Disable SSI capabilities if not required or sanitize all inputs that could be interpreted as directives."
    },
    {
        name: "Application is vulnerable to XML External Entity (XXE) Injection",
        description: "XML supports a facility known as 'external entities', which instruct an XML processor to retrieve and perform an inline include of XML located at a particular URI. An external XML entity can be used to append or modify the document type declaration (DTD) associated with an XML document. An external XML entity can also be used to include XML within the content of an XML document.",
        tags: ["XXE Injection", "XML Handling","Android","Dynamic"],
        comments: "",
        recommendations:"Restrict XML external entities and use less complex data formats where possible."
    },
    {
        name: "Application is vulnerable to XPath Injection Attack",
        description: "XPath Injection attacks occur when a website uses user-supplied information to construct an XPath query for XML data. By sending intentionally malformed information to the website, an attacker can find out how the XML data is structured or access data that he may not normally have access to. He may even be able to elevate his privileges on the website if the XML data is being used for authentication (such as an XML-based user file).",
        tags: ["XPath Injection", "XML Data", "Injection Attack","Android","Dynamic"],
        comments: "",
        recommendations:"Sanitize and validate all user inputs used in XPath queries."
    },
    {
        name: "Application's Authentication Can Be Bypassed",
        description: "Applications require authentication to gain access to private information or to execute certain tasks for specific user. But certain application does not properly perform authentication, allowing it to be bypassed through various methods.",
        tags: ["Authentication Bypass", "Security","Android","Dynamic"],
        comments: "",
        recommendations:"Review and enhance authentication mechanisms to prevent bypass."
    },
    {
        name: "Cross-Site Web Socket Hijacking",
        description: "Web sockets are used to handle requests in real-time, i.e., chat and online gaming applications. It helps to create & maintain a bi-directional HTTP connection between the client & server in real time. CSWSH, aka 'cross-origin web socket hijacking,' occurs when a WebSocket handshake request depends on HTTP cookies for session handling and does not contain any CSRF tokens or other unpredictable values.",
        tags: ["CSWSH", "Web Sockets", "Session Security","Android","Dynamic"],
        comments: "",
        recommendations:"Implement CSRF tokens and validate origin headers in WebSocket connections."
    },
    {
        name: "HTTP Request Smuggling Attack",
        description: "HTTP request smuggling is a technique to take advantage of discrepancies in parsing non-RFC-compliant HTTP requests between two HTTP devices (the user and the web server). An attacker may be able to 'smuggle' malicious requests through a packet inspector, firewall or web proxy server. This technique may leave the web server vulnerable to various attacks such as web cache poisoning, or allow the attacker to request protected files on the web server.",
        tags: ["HTTP Smuggling", "Web Server Security","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure proper handling and validation of HTTP request headers and payloads."
    },
    {
        name: "Improper Token Management",
        description: "The token does not validate for below points at server side - 1. The same token can be used by different users/sessions. 2. The token does not expire after the used or after the session expires. 3. The token is not random and is guessable. 4. The token is shared in cookie and not in the HTML form/HTTP Headers.",
        tags: ["Token Management", "Session Security","Android","Dynamic"],
        comments: "",
        recommendations:"Implement secure token generation and management strategies."
    },
    {
        name: "Insecure Deserialization",
        description: "Insecure Deserialization is a vulnerability that occurs when untrusted data is used to abuse the logic of an application. Successful insecure deserialization attacks could allow an attacker to carry out denial-of-service (DoS), authentication bypasses, and remote code execution attacks.",
        tags: ["Insecure Deserialization", "Application Security","Android","Dynamic"],
        comments: "",
        recommendations:"Avoid deserializing data from untrusted sources and implement integrity checks."
    },
    {
        name: "Insecure Direct Object References",
        description: "Applications frequently use the actual name or key of an object when generating web pages. Applications don’t always verify the user is authorized for the target object. This results in an insecure direct object reference flaw. Testers can easily manipulate parameter values to detect such flaws and code analysis quickly shows whether authorization is properly verified.",
        tags: ["IDOR", "Access Control","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure robust authorization checks before accessing any objects."
    },
    {
        name: "Local File Inclusion Attack – LFI",
        description: "Local File Inclusion vulnerability allows an attacker to include files that are already locally present on the server, usually exploiting a 'dynamic file inclusion' mechanisms implemented in the target application.",
        tags: ["Local File Inclusion", "LFI", "File Inclusion","Android","Dynamic"],
        comments: "",
        recommendations:"Validate and sanitize all file paths to prevent unauthorized file access."
    },
    {
        name: "Malicious File Can Be Uploaded on the Server",
        description: "The application has the option to upload files. Here the application only allows specific files to be uploaded but in spite of the restriction, an adversary is able to upload a malicious file to the web server as validation is not done properly.",
        tags: ["File Upload", "Malicious File","Android","Dynamic"],
        comments: "",
        recommendations:"Implement comprehensive file validation and sanitization before accepting uploads."
    },
    {
        name: "Password Spoofing via 'Forgot Password'",
        description: "An attacker can exploit weakly implemented forgot password feature by stealing the clear text password sent, or by exploiting the token generated, or by exploiting the weak security questions.",
        tags: ["Password Spoofing", "Authentication Flaw","Android","Dynamic"],
        comments: "",
        recommendations:"Strengthen the forgot password process including secure token management and complex security questions."
    },
    {
        name: "Server Side Template Injection",
        description: "Template engines are widely used by web applications to present dynamic data via web pages and emails. Template Injection occurs when user input is embedded in a template in an unsafe manner. It can arise both through developer error and through the exposure of templates in an attempt to offer rich functionality.",
        tags: ["Server Side Template Injection", "Template Engines","Android","Dynamic"],
        comments: "",
        recommendations:"Sanitize and validate all inputs that may be used in templates to prevent injection."
    },
    {
        name: "Application is vulnerable to PHP Object Injection Attack",
        description: "PHP Object Injection is an application-level vulnerability that could allow an attacker to perform different kinds of malicious attacks. The vulnerability occurs when user-supplied input is not properly sanitized before being passed to the unserialize() PHP function.",
        tags: ["PHP Object Injection", "Deserialization","Android","Dynamic"],
        comments: "",
        recommendations:"Avoid using unserialize() on untrusted data. Implement integrity checks and input validation."
    },
    {
        name: "Abuse of Send-Mail Functionality",
        description: "If an attacker can control the From, To, Subject, and Body of a message and there are no anti-automation controls in place, email functions can be turned into spam-relay vehicles.",
        tags: ["Email Abuse", "Spam","Android","Dynamic"],
        comments: "",
        recommendations:"Implement CAPTCHA and rate limiting to prevent abuse of mail functionalities."
    },
    {
        name: "Abuse of Send-SMS Functionality",
        description: "If an attacker can control the From, To, Subject, and Body of a message and there are no anti-automation controls, SMS functions can be turned into spam-relay vehicles/OTP Retrieval.",
        tags: ["SMS Abuse", "OTP Fraud","Android","Dynamic"],
        comments: "",
        recommendations:"Introduce rate limiting and authentication checks on SMS functionalities to prevent abuse."
    },
    {
        name: "Application is vulnerable to XML Injection Attack",
        description: "XML injection occurs when: 1. Data enters a program from an untrusted source. 2. The data is written to an XML document. The semantics of XML documents and messages can be altered if an attacker has the ability to write raw XML.",
        tags: ["XML Injection", "Data Manipulation","Android","Dynamic"],
        comments: "",
        recommendations:"Sanitize all XML data inputs and implement proper encoding when handling XML data."
    },
    {
        name: "Application is vulnerable to ClickJacking Attack",
        description: "Clickjacking is a malicious technique of tricking Web users into revealing confidential information or taking control of a user's computer while clicking on seemingly innocuous Web pages. A click-jacked page tricks a user into performing undesired actions by clicking on a concealed link.",
        tags: ["ClickJacking", "UI Redressing","Android","Dynamic"],
        comments: "",
        recommendations:"Use frame busting techniques, X-Frame-Options headers, and Content Security Policy to prevent clickjacking."
    },
    {
        name: "Application is vulnerable to Content Spoofing Attack",
        description: "Content spoofing, also referred to as content injection or virtual defacement, is an attack targeting a user made possible by an injection vulnerability in a web application. When an application does not properly handle user supplied data, an attacker can supply content to a web application, typically via a parameter value, that is reflected back to the user. This presents the user with a modified page under the context of the trusted domain.",
        tags: ["Content Spoofing", "Content Injection","Android","Dynamic"],
        comments: "",
        recommendations:"Implement content validation and encoding to prevent untrusted data from being reflected back to users."
    },
    {
        name: "Application is vulnerable to Credential/Session Prediction Attack",
        description: "Credential/Session Prediction is a method of hijacking or impersonating a web site user. Deducing or guessing the unique value that identifies a particular session or user accomplishes the attack.",
        tags: ["Session Prediction", "Credential Hijacking","Android","Dynamic"],
        comments: "",
        recommendations:"Use strong session management policies with high entropy tokens that cannot be easily guessed."
    },
    {
        name: "Application is vulnerable to CRLF/Response Splitting Attack",
        description: "CRLF (Carriage Return and Line Feed) is a very significant sequence of characters for programmers. These two special characters represent many Internet protocols End Of Line (EOL) markers. If a malicious user is able to inject his own CRLF sequence into an HTTP stream, he is able to control the way a web application functions maliciously.",
        tags: ["CRLF Injection", "HTTP Response Splitting","Android","Dynamic"],
        comments: "",
        recommendations:"Validate and sanitize all inputs to remove or encode CRLF characters."
    },
    {
        name: "Application is vulnerable to Cross Origin Resource Sharing",
        description: "CORS is a mechanism that enables a web browser to perform cross-origin requests. However, it is vulnerable to cross-domain-based attacks when a website's CORS policy is poorly configured and implemented.",
        tags: ["CORS", "Cross-Domain Attacks","Android","Dynamic"],
        comments: "",
        recommendations:"Review and tighten CORS policies to ensure only trusted domains can interact with the web application."
    },
    {
        name: "Application is vulnerable to Email Flooding Attack",
        description: "Email Flooding is a form of net abuse consisting of sending huge volumes of email to an address in an attempt to overflow the mailbox or overwhelm the server where the email address is hosted in a denial-of-service attack.",
        tags: ["Email Flooding", "Denial of Service","Android","Dynamic"],
        comments: "",
        recommendations:"Implement rate limiting and CAPTCHA to mitigate abuse."
    },
    {
        name: "Application is vulnerable to HTTP Parameter Pollution",
        description: "HTTP Parameter Pollution is a vulnerability in which an attacker appends extra parameters to an HTTP request to perform or achieve a specific malicious task/attack in order to get unexpected behavior of the web application. This vulnerability can be found on the client-side or the server-side.",
        tags: ["HTTP Parameter Pollution", "Web Application Security","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure robust input validation and handle parameters securely."
    },
    {
        name: "Application is vulnerable to Improper Session Management",
        description: "Proper authentication and session management is critical to web application security. Flaws in this area frequently involve the failure to protect credentials and session tokens through their lifecycle. These flaws can lead to the hijacking of user or administrative accounts, undermine authorization and accountability controls, and cause privacy violations.",
        tags: ["Session Management", "Authentication","Android","Dynamic"],
        comments: "",
        recommendations:"Use secure session management strategies including secure token handling and expiration."
    },
    {
        name: "Application is vulnerable to OTP Flooding Attack",
        description: "A user can capture the send OTP request and send it multiple times (Sufficiently Huge Count) within a very short span of time. This can trigger the server to invoke OTP functionality continuously and send continuous OTP to users.",
        tags: ["OTP Flooding", "Abuse of Functionality","Android","Dynamic"],
        comments: "",
        recommendations:"Implement rate limiting and monitoring mechanisms to detect and prevent OTP abuse."
    },
    {
        name: "Application is vulnerable to Poodle Attack",
        description: "The POODLE attack (Padding Oracle On Downgraded Legacy Encryption) is a man-in-the-middle exploit which takes advantage of Internet and security software client's fallback to SSL 3.0. If attackers successfully exploit this vulnerability, on average, they only need to make SSL 3.0 requests to reveal one byte of encrypted messages.",
        tags: ["Poodle Attack", "SSL 3.0","Android","Dynamic"],
        comments: "",
        recommendations:"Disable SSL 3.0 on all servers and use strong encryption protocols such as TLS 1.2 or higher."
    },
    {
        name: "Application is vulnerable to URL Redirection Attack",
        description: "The URL redirection service is the web technique for pointing a web page to another URL of your choice. In this attack, an attacker can change the stored redirection URL to the malicious URL of his choice, and if the user clicks on that link, he will become the victim by visiting the fake site.",
        tags: ["URL Redirection", "Phishing","Android","Dynamic"],
        comments: "",
        recommendations:"Validate and sanitize all redirection targets to prevent unauthorized redirects."
    },
    {
        name: "Application is vulnerable to Replay Attack",
        description: "A replay attack is a type of network attack in which a valid data transmission is maliciously repeated or delayed. This is carried out either by the originator or by an adversary who intercepts the data and re-transmits it.",
        tags: ["Replay Attack", "Network Security","Android","Dynamic"],
        comments: "",
        recommendations:"Implement nonce and timestamps to ensure that each authentication session is unique."
    },
    {
        name: "Application is vulnerable to Session Fixation Attack",
        description: "Session Fixation is an attack that permits an attacker to hijack a valid user session. Session Fixation is an attack technique that forces a user's session ID to an explicit value.",
        tags: ["Session Fixation", "Session Hijacking","Android","Dynamic"],
        comments: "",
        recommendations:"Regenerate session IDs after successful authentication and do not accept predefined session IDs."
    },
    {
        name: "Application is vulnerable to SSRF Attack",
        description: "Server Side Request Forgery (SSRF) vulnerabilities let an attacker send crafted requests from the back-end server of a vulnerable web application. Attackers usually use SSRF attacks to target internal systems that are behind firewalls and are not accessible from the external network.",
        tags: ["SSRF", "Server Side","Android","Dynamic"],
        comments: "",
        recommendations:"Validate and sanitize all user inputs and restrict server requests to known safe URLs."
    },
    {
        name: "Application's Apache Server - Status Enabled",
        description: "The Apache webserver module mod_status provides information on an Apache server's activity and performance. The module uses a publicly accessible webpage located at /server-status to provide real-time traffic logs in addition to host information, including CPU usage, current HTTP requests, client IP addresses, requested paths, and processed virtual hosts.",
        tags: ["Apache Status", "Server Monitoring","Android","Dynamic"],
        comments: "",
        recommendations:"Restrict access to the Apache status page to trusted IP addresses."
    },
    {
        name: "Application's OTP Can Be Bypassed",
        description: "A one-time password (OTP) is a password that is used as a second factor authenticator to perform critical transactions providing secure login to users. However, vulnerabilities in the implementation can allow OTPs to be bypassed.",
        tags: ["OTP Bypass", "Two-Factor Authentication","Android","Dynamic"],
        comments: "",
        recommendations:"Implement robust OTP generation and validation mechanisms, and monitor for unusual authentication activities."
    },
    {
        name: "ASP.NET Debugging is Enabled",
        description: "ASP.NET allows remote debugging of web applications if configured to do so. Debugging is subject to access control and requires platform-level authentication. The DEBUG verb is not required for web applications to function and should be disabled in production environments.",
        tags: ["ASP.NET", "Debugging", "Security Risk","Android","Dynamic"],
        comments: "",
        recommendations:"Disable remote debugging in production environments and ensure that the DEBUG verb is blocked at the web server or application gateway."
    },
    {
        name: "ASP.NET Tracing is Enabled",
        description: "ASP.NET tracing is a debugging feature that is designed for use during development to help troubleshoot problems. It discloses sensitive information to users, and if enabled in production contexts may present a serious security threat.",
        tags: ["ASP.NET", "Tracing", "Information Disclosure","Android","Dynamic"],
        comments: "",
        recommendations:"Disable tracing in production environments to prevent leakage of sensitive application or user data."
    },
    {
        name: "Authentication / 2FA Bypass Using Response Manipulation",
        description: "If the application provides a simple and easily guessable response (e.g., true/false, yes/no, 1/0) to the authentication request, an attacker can easily manipulate the invalid response to a valid one and gain access to the user's account.",
        tags: ["Authentication Bypass", "2FA", "Security","Android","Dynamic"],
        comments: "",
        recommendations:"Use complex and unpredictable responses for authentication processes. Implement additional security checks beyond simple binary responses."
    },
    {
        name: "Mobile Number Can Be Bypassed and Used to Perform Critical Transactions",
        description: "An application uses mobile number as authentication factor, to perform critical transactions providing secure login to users. However, vulnerabilities may allow bypassing of mobile number authentication.",
        tags: ["Authentication Bypass", "Mobile Security","Android","Dynamic"],
        comments: "",
        recommendations:"Strengthen mobile number verification processes and implement multi-factor authentication mechanisms."
    },
    {
        name: "OAuth/JWT/SAML Misconfiguration",
        description: "OAuth 2.0, JSON Web Tokens (JWT), and Security Assertion Markup Language (SAML) are standards for securely exchanging information. Misconfigurations can lead to unauthorized access and data breaches.",
        tags: ["OAuth", "JWT", "SAML", "Configuration Error","Android","Dynamic"],
        comments: "",
        recommendations:"Conduct regular security reviews and audits of configuration settings. Ensure proper implementation of authentication standards."
    },
    {
        name: "Options Bleed Apache (Apache < 2234 / < 2427)",
        description: "Vulnerability lies in how Apache handles certain settings in its configuration files. If a limit directive in config file is set to an invalid HTTP method, there is a possibility that this corruption happens. This can leak pieces of arbitrary memory from the server.",
        tags: ["Apache", "Options Bleed", "Memory Leak","Android","Dynamic"],
        comments: "",
        recommendations:"Update Apache to a patched version that addresses the Options Bleed vulnerability. Validate and sanitize all HTTP methods."
    },
    {
        name: "Application is Vulnerable to PDF Tampering Attack",
        description: "PDF documents are currently widely being used & manipulated, both in terms of malware embedding and document forgery, which is crucial for ensuring the integrity of files.",
        tags: ["PDF Security", "Document Tampering","Android","Dynamic"],
        comments: "",
        recommendations:"Implement strong validation and checksum mechanisms to detect and prevent PDF tampering."
    },
    {
        name: "Restricted Files Can Be Viewed by Directory Listing",
        description: "Internet browsers permit users to randomly access directories on the Web server. It is sometimes used to offer files easily on the internet, but if unintended, it can allow an attacker to gain valuable information about your site.",
        tags: ["Directory Listing", "Information Disclosure","Android","Dynamic"],
        comments: "",
        recommendations:"Disable directory listing on the web server and ensure proper access controls are in place."
    },
    {
        name: "Sensitive Information Sent Over Unencrypted Channel",
        description: "Applications frequently fail to encrypt network traffic when it is necessary to protect sensitive communications. Encryption (usually SSL) must be used for all authenticated connections, especially Internet-accessible web pages and backend connections.",
        tags: ["Data Transmission", "Encryption", "SSL/TLS","Android","Dynamic"],
        comments: "",
        recommendations:"Enforce HTTPS for all communications and ensure backend connections also use encrypted channels."
    },
    {
        name: "Valid Account Can Be Brute Forced",
        description: "It was observed that the user account could be brute forced as the account does not get locked after 3/5 invalid attempts. An attacker who knows a valid user’s username can enter and guess the password of the valid user's account.",
        tags: ["Brute Force Attack", "Account Security","Android","Dynamic"],
        comments: "",
        recommendations:"Implement account lockout mechanisms after a few unsuccessful attempts and consider using CAPTCHA to prevent automated attacks."
    },
    {
        name: "XML-RPC is Publicly Available",
        description: "Xmlrpc is a set of implementations that allows software running on disparate operating systems in different environments to make procedure calls over the internet. It uses HTTP to transport the data and XML as the encoding.",
        tags: ["XML-RPC", "API Security","Android","Dynamic"],
        comments: "",
        recommendations:"Restrict access to XML-RPC endpoints and monitor for unusual API calls that could indicate an attack."
    },
    {
        name: "Form Action Hijacking",
        description: "Form action hijacking allows an attacker to specify the action URL of a form via a parameter. An attacker can construct a URL that will modify the action URL of a form to point to the attacker’s server. Form content including CSRF tokens, user-entered parameter values, and any other of the form's content will be delivered to the attacker via the hijacked action URL.",
        tags: ["Form Hijacking", "Data Exfiltration","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure that form actions are dynamically generated server-side and are not modifiable through client-side manipulation."
    },
    {
        name: "Application is Vulnerable to Race Condition Attack",
        description: "When an application performs two or more operations at the same time, but because of the nature of the system, the operations must be done in the proper sequence to be done correctly. This technique takes advantage of a time gap between the moment a service is initiated and the moment a security control takes effect.",
        tags: ["Race Condition", "Concurrency Issues","Android","Dynamic"],
        comments: "",
        recommendations:"Implement proper synchronization in critical sections of the code to handle concurrent operations securely."
    },
    {
        name: "Allows Disposable Email Addresses",
        description: "Disposable email address, also known as DEA or dark mail, refers to an approach where a unique email address is used for every contact, entity, or limited time or number of uses. It is a service that allows one to receive an email at a temporary address that self-destructed after a certain time elapses.",
        tags: ["Disposable Email", "Account Integrity","Android","Dynamic"],
        comments: "",
        recommendations:"Validate email addresses during account registration and periodically verify them to prevent abuse by temporary email services."
    },
    {
        name: "Application Accepts Special Character as User Input",
        description: "Application allows user to enter special character in input fields.",
        tags: ["Input Validation", "Security","Android","Dynamic"],
        comments: "",
        recommendations:"Sanitize and validate all user inputs to prevent injection attacks."
    },
    {
        name: "Application Displays Web Server Banner",
        description: "HTTP responses from the web server reveal information about the type and version of the web server, which can be used by an attacker.",
        tags: ["Information Disclosure", "Web Server Configuration","Android","Dynamic"],
        comments: "",
        recommendations:"Configure the web server to suppress server banners and other identifiable information from HTTP responses."
    },
    {
        name: "Application Does Not Have a Strong Password Policy",
        description: "The application does not impose a password policy properly, such as password complexity is not maintained, password length is not strong, history is not maintained, etc.",
        tags: ["Password Policy", "Authentication","Android","Dynamic"],
        comments: "",
        recommendations:"Implement and enforce a strong password policy that includes requirements for complexity, length, and history."
    },
    {
        name: "Application is Vulnerable to HTTP Host Header Injection Attack",
        description: "Host header is used by a web server to decide which website should process the received HTTP request. If the application relies on the value of the Host header for writing links without HTML-encoding, importing scripts, deciding the location to redirect to, or even generate password reset links with its value without proper filtering, validation, and sanitization, then it can lead to several vulnerabilities like Cache Poisoning, Cross-Site Scripting, etc.",
        tags: ["Host Header Injection", "HTTP Security","Android","Dynamic"],
        comments: "",
        recommendations:"Validate and sanitize the Host header and all other HTTP headers to prevent injection attacks."
    },
    {
        name: "Application is Vulnerable to Simultaneous Login",
        description: "The application allows the same user to login simultaneously from different locations at the same time.",
        tags: ["Simultaneous Login", "Session Management","Android","Dynamic"],
        comments: "",
        recommendations:"Limit simultaneous sessions per user account or implement mechanisms to detect and prevent concurrent logins from different locations."
    },
    {
        name: "Application Supports Weak Ciphers/Encoding",
        description: "A cipher is an algorithm for performing encryption or decryption. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility that the encryption could be cracked. The larger the key size, the stronger the cipher.",
        tags: ["Weak Ciphers", "Encryption", "Security","Android","Dynamic"],
        comments: "",
        recommendations:"Upgrade to strong ciphers with sufficient key lengths to ensure robust encryption. Regularly update cryptographic practices to adhere to current security standards."
    },
    {
        name: "Application Throws ODBC/SQL Error Message",
        description: "The ODBC error message may disclose sensitive information and this information can be used by an attacker to mount new attacks or to enlarge the attack surface. In rare conditions, this may be a clue for an SQL Injection vulnerability.",
        tags: ["Error Handling", "Information Disclosure", "ODBC","Android","Dynamic"],
        comments: "",
        recommendations:"Implement proper error handling that masks sensitive details from the users and logs them securely for internal use only."
    },
    {
        name: "Application's Hidden Directory Detected",
        description: "Application's directory which should not be accessible by normal user is detected, the information may help an attacker to develop further attacks against the application.",
        tags: ["Hidden Directories", "Unauthorized Access","Android","Dynamic"],
        comments: "",
        recommendations:"Use robust access controls and regularly update and review configurations to ensure that hidden directories are not accessible to unauthorized users."
    },
    {
        name: "Application's Request/Response Reveals Sensitive Information",
        description: "Sensitive information in Request and Response should be encrypted with the proper technique with salting. E.g.: Password, Account Details, Personal Identity information, Etc",
        tags: ["Data Exposure", "Encryption","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure that all sensitive data transmitted in requests and responses is properly encrypted and secure transmission protocols are used."
    },
    {
        name: "Application's Source Code Reveals Sensitive Information",
        description: "The application's source code reveals sensitive details. Obtaining this grants the attacker deeper knowledge of the logic behind the Web application, how the application handles requests and their parameters, the structure of the database, vulnerabilities in the code, and source code comments.",
        tags: ["Source Code Exposure", "Information Disclosure","Android","Dynamic"],
        comments: "",
        recommendations:"Restrict access to source code and ensure that it does not include sensitive information or credentials. Use environment variables for sensitive data."
    },
    {
        name: "Arbitrary Methods Enabled on Server",
        description: "HTTP offers a number of methods that can be used to perform actions on the web server. An attacker can manipulate these verbs to bypass the security controls.",
        tags: ["HTTP Methods", "Server Security","Android","Dynamic"],
        comments: "",
        recommendations:"Restrict the use of HTTP methods to those necessary for application functionality and disable unused methods."
    },
    {
        name: "Automated Tools Can Be Used to Bring Down the Server",
        description: "Automated programs can be used to fill the forms such as registration page to send a large number of requests in a short time to bring down the server and make it unavailable for users.",
        tags: ["DoS Attack", "CAPTCHA","Android","Dynamic"],
        comments: "",
        recommendations:"Implement CAPTCHA and rate limiting to prevent automated attacks and reduce the risk of Denial of Service (DoS)."
    },
    {
        name: "Basic Authentication is Used in the Application",
        description: "In the context of an HTTP transaction, BASIC authentication is a method for an HTTP user agent to provide a user name and password when making a request. With Basic Authentication, the user credentials are sent as cleartext and because HTTPS is not used, they are vulnerable to packet sniffing.",
        tags: ["Basic Authentication", "Credentials Exposure","Android","Dynamic"],
        comments: "",
        recommendations:"Replace basic authentication with more secure methods such as OAuth or token-based authentication and ensure HTTPS is used to encrypt all communications."
    },
    {
        name: "CAPTCHA Not Implemented Properly",
        description: "Automated programs can be used to fill the forms such as registration page to send a large number of requests in a short time to bring down the server and make it unavailable for users.",
        tags: ["CAPTCHA", "Security Misconfiguration","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure that CAPTCHA is implemented correctly and effectively on all forms to prevent automated abuse."
    },
    {
        name: "Default Web Page Found on the Application Server",
        description: "Every website is built inside directories on a Web server. But sometimes, when you go to a URL, there is no file listed in the URL. This file is the default page for that directory.",
        tags: ["Default Page", "Information Leakage","Android","Dynamic"],
        comments: "",
        recommendations:"Configure servers to not use default pages and ensure that no sensitive information is disclosed through default pages."
    },
    {
        name: "Error Message Reveals Sensitive Information",
        description: "The application does not handle all errors properly. Some error messages contain information about the application. The application generates an error message that includes sensitive information about its environment, users, or associated data.",
        tags: ["Error Handling", "Information Disclosure","Android","Dynamic"],
        comments: "",
        recommendations:"Implement generic error messages for end-users while logging detailed error messages securely for developers."
    },
    {
        name: "HTTP Methods Enabled on Server",
        description: "HTTP offers a number of methods that can be used to perform actions on the web server. Many of these methods are designed to aid developers in deploying and testing HTTP applications. These HTTP methods can be used for nefarious purposes if the web server is misconfigured.",
        tags: ["HTTP Methods", "Server Security","Android","Dynamic"],
        comments: "",
        recommendations:"Restrict unnecessary HTTP methods and allow only essential methods like GET and POST."
    },
    {
        name: "HTTP Request Can Be Converted from POST to GET",
        description: "Changing the request method to GET can expose sensitive information in clear text via browser history, Referrer headers, server logs, proxy logs, and may bypass certain security protections.",
        tags: ["Request Manipulation", "Information Exposure","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure that sensitive data is never passed in URLs and enforce proper request method validation."
    },
    {
        name: "HTTPOnly Attribute Not Set in Session Cookie",
        description: "HTTPOnly is an additional flag in the cookie response header, which helps restrict scripts from accessing restricted cookies. In the absence of the HTTPOnly attribute in the set-cookie parameter, an attacker can exploit this vulnerability to gain information stored in a cookie or launch session hijacking attacks.",
        tags: ["Session Security", "Cookies","Android","Dynamic"],
        comments: "",
        recommendations:"Set the HTTPOnly flag on session cookies to prevent JavaScript-based attacks."
    },
    {
        name: "HTTPS and Mixed Content Vulnerability",
        description: "HTTPS is used to make communication between the server and the browser secure. However, a problem occurs when an HTTPS page loads HTTP content, known as mixed content vulnerability (active/passive).",
        tags: ["Mixed Content", "HTTPS","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure all content is loaded over HTTPS, and enable Content Security Policy (CSP) to prevent mixed content vulnerabilities."
    },
    {
        name: "Invalid SSL Certificate",
        description: "This SSL certificate is either expired or not yet valid. Some browsers will continue connecting to the site after presenting the user with a warning, while others will prompt the user to proceed. These warnings can cause users to question the authenticity of the site.",
        tags: ["SSL/TLS", "Encryption","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure SSL certificates are valid, properly configured, and regularly renewed to maintain secure connections."
    },
    {
        name: "Lack of Verification Email Upon Account Creation",
        description: "When registering a new account, no verification link is sent to the email for confirmation. The account is directly activated and can be used without confirming the email. This allows attackers to use fake or stolen emails for unauthorized account creation.",
        tags: ["Account Security", "Email Verification","Android","Dynamic"],
        comments: "",
        recommendations:"Require email verification before allowing account activation to prevent unauthorized sign-ups."
    },
    {
        name: "Missing HSTS Header",
        description: "The application is not using the HSTS header. If HTTP Strict Transport Security (HSTS) is enabled, the browser will prevent any communications from being sent over HTTP to the specified domain and will enforce HTTPS.",
        tags: ["HSTS", "Transport Security","Android","Dynamic"],
        comments: "",
        recommendations:"Enable HTTP Strict Transport Security (HSTS) to enforce HTTPS usage."
    },
    {
        name: "Missing Security Headers",
        description: "Adding security headers can help prevent various attacks, including Clickjacking, MIME sniffing, and XSS.",
        tags: ["Security Headers", "Web Security","Android","Dynamic"],
        comments: "",
        recommendations:"Implement security headers such as Content Security Policy (CSP), X-Frame-Options, X-Content-Type-Options, and Referrer-Policy."
    },
    {
        name: "Non-HTML Contents Can Be Stolen",
        description: "Authenticated Non-HTML content (e.g., images, files, PDFs, CSVs, etc.) can be accessed directly without authentication, leading to potential data leakage.",
        tags: ["File Security", "Unauthorized Access","Android","Dynamic"],
        comments: "",
        recommendations:"Restrict direct access to non-HTML files and enforce authentication before serving protected content."
    },
    {
        name: "NTLM Authentication is Used in the Application",
        description: "NTLM is widely deployed, even on new systems, often for compatibility with older systems. However, it remains vulnerable to credentials forwarding attacks, which are a variant of the reflection attack addressed by Microsoft security update MS08-068.",
        tags: ["NTLM Authentication", "Credential Security","Android","Dynamic"],
        comments: "",
        recommendations:"Disable NTLM authentication and switch to more secure authentication methods like Kerberos or OAuth."
    },
    {
        name: "Older Version of Programming Language Found",
        description: "The server reveals information about the type and version of the web server. The application is using an older version of the back-end programming language, which may contain known security flaws that can be exploited by attackers.",
        tags: ["Programming Language Version", "Server Security","Android","Dynamic"],
        comments: "",
        recommendations:"Upgrade to the latest stable version of the programming language and apply security patches regularly."
    },
    {
        name: "Older Version of SSL Supported",
        description: "TLS is a critical security protocol that provides confidentiality and integrity of data in transit between clients and servers. TLS 1.0 or 1.1 are older versions that rely on MD5, SHA-1, and contain other flaws. To best safeguard data, it is important to use this protocol's latest and more secure versions.",
        tags: ["SSL/TLS Security", "Encryption","Android","Dynamic"],
        comments: "",
        recommendations:"Disable TLS 1.0 and TLS 1.1 support and enforce TLS 1.2 or TLS 1.3 for all encrypted communications."
    },
    {
        name: "Weak OTP/PIN Implementation",
        description: "A one-time password (OTP)/PIN is used as a second factor authenticator to perform critical transactions like secure logins. However, it is insecure if: 1) OTP/PIN is shared with the client for client-side validation, 2) The OTP/PIN verification response is exposed as a flag/status in the response, 3) OTP/PIN is generated using weak/random methods that are predictable, 4) Server-side OTP/PIN verification is inadequate.",
        tags: ["Weak OTP", "Authentication Security","Android","Dynamic"],
        comments: "",
        recommendations:"Use strong cryptographic methods to generate OTP/PINs, perform all validation on the server, and avoid exposing verification responses in API responses."
    },
    {
        name: "Path Attribute Not Set in Session Cookie",
        description: "If the path attribute is set too loosely, then it could leave the application vulnerable to attacks by other applications on the same server.",
        tags: ["Session Security", "Cookie Security","Android","Dynamic"],
        comments: "",
        recommendations:"Set the path attribute in session cookies to restrict access to specific application paths."
    },
    {
        name: "Programming Language and Version Disclosure",
        description: "HTTP responses from the web server reveal information about the programming language being used in the application, which can be exploited by attackers.",
        tags: ["Information Disclosure", "Security Misconfiguration","Android","Dynamic"],
        comments: "",
        recommendations:"Configure the server to suppress programming language version details in HTTP response headers."
    },
    {
        name: "Second Factor Authentication Missing for Critical Operations",
        description: "Many people use weak passwords. Even strong passwords do not always ensure adequate security. Two-factor authentication (2FA) is an authentication method in which a user is granted access only after successfully presenting more than one type of evidence, such as an OTP, security question, or biometric verification.",
        tags: ["2FA", "Authentication Security","Android","Dynamic"],
        comments: "",
        recommendations:"Enforce 2FA for all critical transactions and high-privilege actions."
    },
    {
        name: "Secure Attribute is Not Set in Session Cookie",
        description: "The secure attribute is a flag indicating that a cookie should only be used under a secure server condition, such as SSL/TLS.",
        tags: ["Cookie Security", "Session Management","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure that the secure flag is set on all session cookies to prevent transmission over non-secure connections."
    },
    {
        name: "Sensitive Data Exposed in URLs (GET)",
        description: "The GET request of every web page you visit is recorded in your browser history file. An attacker can steal sensitive information from browser history, logs, and referrer headers.",
        tags: ["Sensitive Data Exposure", "URL Security","Android","Dynamic"],
        comments: "",
        recommendations:"Never pass sensitive information in GET requests; use POST instead. Implement mechanisms to obfuscate or encrypt sensitive parameters."
    },
    {
        name: "Sensitive Data Stored in Unencrypted ViewState",
        description: "ViewState allows the state of objects to be stored in a hidden field on the page. ViewState is transported to the client and back to the server and is not stored on the server or any other external source. If not encrypted, it can expose sensitive application data.",
        tags: ["ViewState Security", "Data Protection","Android","Dynamic"],
        comments: "",
        recommendations:"Enable ViewState encryption and MAC validation to prevent tampering and exposure of sensitive information."
    },
    {
        name: "Sensitive Information Gets Stored in Cache",
        description: "The cache is a component that transparently stores data so that future requests for that data can be served faster. Sometimes, pages with sensitive information are also stored in cache, which an attacker can exploit to access stored confidential data.",
        tags: ["Cache Security", "Sensitive Data Exposure","Android","Dynamic"],
        comments: "",
        recommendations:"Configure cache settings to prevent sensitive data from being stored. Use cache-control headers such as 'Cache-Control: no-store' and 'Pragma: no-cache'."
    },
    {
        name: "Client-Side Renegotiation is Supported",
        description: "The SSL handshake is only done at the beginning of a secure session and only if security is required. Servers are not prepared to handle a large number of SSL handshakes, which can be exploited for denial-of-service attacks.",
        tags: ["SSL/TLS Security", "Renegotiation","Android","Dynamic"],
        comments: "",
        recommendations:"Disable client-side renegotiation in SSL/TLS configurations to prevent resource exhaustion attacks."
    },
    {
        name: "Application is Vulnerable to CRIME Attack",
        description: "Compression Ratio Info-leak Made Easy (CRIME) is a security exploit against secret web cookies over connections using the HTTPS and SPDY protocols that also use data compression.",
        tags: ["CRIME Attack", "TLS Compression","Android","Dynamic"],
        comments: "",
        recommendations:"Disable TLS compression to mitigate CRIME attacks."
    },
    {
        name: "Insecure Server-Side Renegotiation is Supported",
        description: "A vulnerability in the way SSL and TLS protocols allow renegotiation requests may allow an attacker to inject plaintext into an application protocol stream. This could result in a situation where the attacker may be able to issue commands to the server that appear to be coming from a legitimate source.",
        tags: ["SSL/TLS Security", "Renegotiation Attack","Android","Dynamic"],
        comments: "",
        recommendations:"Disable insecure renegotiation in SSL/TLS configurations to prevent man-in-the-middle attacks."
    },
    {
        name: "Server-Side Validation Not in Place",
        description: "Validations can be performed on the server side or on the client side. If the application relies only on client-side validation, an attacker can bypass these checks and submit malicious input.",
        tags: ["Input Validation", "Server Security","Android","Dynamic"],
        comments: "",
        recommendations:"Always implement server-side validation to enforce security rules and prevent malicious input manipulation."
    },
    {
        name: "Session Timeout is Not Set Properly",
        description: "The Timeout property specifies the time-out period assigned to the session object for the application. If the session does not time out properly, an attacker could hijack an inactive session.",
        tags: ["Session Management", "Security Misconfiguration","Android","Dynamic"],
        comments: "",
        recommendations:"Set session timeouts based on risk factors and implement automatic logout for inactive sessions."
    },
    {
        name: "Session Token Going in Other Parts Other Than Cookie",
        description: "If a session token is transmitted outside of secure cookies, it can be stolen and used for session hijacking attacks.",
        tags: ["Session Security", "Token Exposure","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure that session tokens are only transmitted via secure cookies using the 'HttpOnly' and 'Secure' flags."
    },
    {
        name: "The Application Does Not Log Off Users on Suspicious Requests (Critical Application)",
        description: "The application does not forcefully terminate a user's session even when malicious activity is detected. This enables an adversary to find weaknesses in the application and exploit them further.",
        tags: ["Session Management", "Intrusion Detection","Android","Dynamic"],
        comments: "",
        recommendations:"Implement anomaly detection and force session termination for suspicious activities."
    },
    {
        name: "Token Leakage via Referer - Untrusted 3rd Party",
        description: "The HTTP referer is an optional HTTP header field that identifies the address of the webpage which is linked to the resource being requested. The referrer header may contain sensitive tokens that can be leaked to untrusted third-party websites.",
        tags: ["Token Leakage", "Referer Security","Android","Dynamic"],
        comments: "",
        recommendations:"Use 'Referrer-Policy: no-referrer' or 'Referrer-Policy: same-origin' to prevent token exposure via HTTP referers."
    },
    {
        name: "Using Known Vulnerable Components",
        description: "It is very common for applications to include components with known security vulnerabilities. These components could include the operating system, CMS, web server, plugins, or libraries.",
        tags: ["Software Security", "Vulnerable Components","Android","Dynamic"],
        comments: "",
        recommendations:"Regularly update all components, remove outdated or unused dependencies, and scan for vulnerabilities in third-party libraries."
    },
    {
        name: "Valid User's Details Can Be Enumerated",
        description: "The application does not handle all errors properly. If the application displays different error messages when a wrong username or a wrong password are entered, then valid user details can be enumerated by attackers.",
        tags: ["User Enumeration", "Authentication Security","Android","Dynamic"],
        comments: "",
        recommendations:"Implement generic error messages for login failures to prevent user enumeration attacks."
    },
    {
        name: "Web Service Disclosed",
        description: "Web services provide a functional interface for application communication. If exposed publicly without access control, attackers can discover endpoints and exploit vulnerabilities.",
        tags: ["Web Service Security", "Information Disclosure","Android","Dynamic"],
        comments: "",
        recommendations:"Restrict access to web services and require authentication for sensitive API endpoints."
    },
    {
        name: "WebDAV Extensions Are Enabled",
        description: "WebDAV is a set of HTTP protocol extensions that allow collaborative editing and file management. If enabled unnecessarily, it increases attack surface and may expose sensitive files.",
        tags: ["WebDAV", "Server Security","Android","Dynamic"],
        comments: "",
        recommendations:"Disable WebDAV if not needed and restrict access to sensitive directories."
    },
    {
        name: "Content Security Policy (CSP) Headers Not Set Properly",
        description: "Content Security Policy (CSP) adds an extra layer of security by defining allowed content sources. If misconfigured, it can leave the application vulnerable to attacks such as Cross-Site Scripting (XSS).",
        tags: ["CSP", "XSS Prevention","Android","Dynamic"],
        comments: "",
        recommendations:"Enforce a strict Content-Security-Policy header to restrict the loading of external scripts, styles, and resources."
    },
    {
        name: "ASP.NET ViewState Without MAC Enabled",
        description: "ViewState in ASP.NET persists UI state between requests. If MAC (Message Authentication Code) is not enabled, attackers can manipulate the ViewState data, leading to possible code injection or data leakage.",
        tags: ["ViewState Security", "ASP.NET","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure that ViewStateMAC is enabled and ViewState is encrypted to prevent tampering."
    },
    {
        name: "WebSocket URL Poisoning",
        description: "WebSocket URL poisoning occurs when an application constructs WebSocket connections based on user-controllable input. An attacker can use this vulnerability to open a WebSocket connection to a malicious server.",
        tags: ["WebSocket Security", "URL Manipulation","Android","Dynamic"],
        comments: "",
        recommendations:"Validate and sanitize WebSocket URLs to ensure they are only connecting to trusted endpoints."
    },
    {
        name: "Application is Vulnerable to JSON Injection Attack",
        description: "JSON Injection occurs when untrusted data is not sanitized before being written into a JSON structure. If an attacker injects malicious payloads into JSON objects, it can lead to data corruption or further exploitation.",
        tags: ["JSON Security", "Injection Attack","Android","Dynamic"],
        comments: "",
        recommendations:"Sanitize all user input before inserting it into JSON responses or parsing it on the client side."
    },
    {
        name: "Application Supports Weak Encodings",
        description: "Encoding converts plain text data into another format. If weak encoding methods are used, attackers may be able to easily decode sensitive information.",
        tags: ["Weak Encoding", "Data Protection","Android","Dynamic"],
        comments: "",
        recommendations:"Use strong encoding and encryption methods to protect sensitive data and prevent unauthorized access."
    },
    {
        name: "Application is Vulnerable to ROBOT Attack",
        description: "ROBOT (Return Of Bleichenbacher's Oracle Threat) is an attack that exploits weaknesses in RSA encryption (PKCS#1v1.5), allowing attackers to decrypt messages or perform signing operations using a TLS server’s private key.",
        tags: ["ROBOT Attack", "RSA Security","Android","Dynamic"],
        comments: "",
        recommendations:"Disable RSA cipher suites that use PKCS#1v1.5 and prefer more secure algorithms like ECDSA or RSA-PSS."
    },
    {
        name: "Missing Web API Rate Limiting",
        description: "Web API rate limiting controls the number of requests a user can make within a given period. If rate limiting is not enforced, attackers can perform brute-force attacks or API abuse.",
        tags: ["API Security", "Rate Limiting","Android","Dynamic"],
        comments: "",
        recommendations:"Implement API rate limiting with techniques like request throttling, token-based access control, or IP-based rate restrictions."
    },
    {
        name: "Application is Accessible by IP Address",
        description: "Using IP addresses implies that you cannot use HTTPS with a valid certificate. Also, if your site is accessible via an IP address (e.g., http://1.2.3.4/), it may not enforce limitations on the Host header, potentially allowing attackers to access it via arbitrary domains. This also rules out DDoS mitigation using distributed caching networks.",
        tags: ["IP Exposure", "Host Header Misconfiguration","Android","Dynamic"],
        comments: "",
        recommendations:"Enforce access via domain names and configure the web server to reject direct IP-based requests."
    },
    {
        name: "Internal IP Disclosure",
        description: "A string matching an internal IPv4 address was found on this page. This may disclose information about the IP addressing scheme of the internal network, aiding attackers in targeting internal infrastructure.",
        tags: ["Information Disclosure", "Internal Network Exposure","Android","Dynamic"],
        comments: "",
        recommendations:"Avoid exposing internal IP addresses in responses, headers, or error messages. Use NAT and proper network segmentation."
    },
    {
        name: "Internal Path Disclosure",
        description: "The application discloses physical paths of resources present on the server. This can help an attacker understand the file system structure and identify potential vulnerabilities.",
        tags: ["Path Disclosure", "Information Leakage","Android","Dynamic"],
        comments: "",
        recommendations:"Sanitize error messages and responses to avoid revealing internal file system structures."
    },
    {
        name: "Predictable Resource Location",
        description: "Predictable Resource Location is an attack technique used to uncover hidden website content and functionality by guessing file and directory names. These files may contain sensitive information about the website, databases, credentials, and internal structures.",
        tags: ["Directory Enumeration", "Sensitive Data Exposure","Android","Dynamic"],
        comments: "",
        recommendations:"Use security through obscurity techniques, implement access controls, and configure proper permissions on sensitive directories."
    },
    {
        name: "Robots.txt Found on Site",
        description: "The robots.txt file is used to control the actions of web crawlers and indexers. However, attackers can analyze this file to discover restricted paths or sensitive directories that should not be exposed.",
        tags: ["Information Disclosure", "Web Crawlers","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure robots.txt does not reveal sensitive directories or files. Use authentication controls for true access restriction."
    },
    {
        name: "Unwanted Ports and Services",
        description: "Open ports refer to TCP or UDP ports configured to accept packets. Attackers often scan for open ports to identify vulnerable services and exploit weaknesses in exposed services.",
        tags: ["Port Security", "Network Exposure","Android","Dynamic"],
        comments: "",
        recommendations:"Close unused ports and restrict access to necessary services using firewall rules and security policies."
    },
    {
        name: "Long Redirection Response",
        description: "Redirection responses should not contain sensitive data in the response body. A long redirection response could indicate that sensitive data is being exposed inappropriately before the redirection takes place.",
        tags: ["Redirection Security", "Information Leakage","Android","Dynamic"],
        comments: "",
        recommendations:"Ensure redirection responses do not contain sensitive information in the response body."
    },
    {
        name: "Content Type Incorrectly Stated",
        description: "The Content-Type header informs browsers about the expected data format. If misconfigured or missing, browsers may incorrectly interpret the data, leading to security risks such as MIME sniffing attacks.",
        tags: ["Content Security", "MIME Type Enforcement","Android","Dynamic"],
        comments: "",
        recommendations:"Set proper Content-Type headers and enforce strict MIME type handling using 'X-Content-Type-Options: nosniff'."
    },
    {
        name: "Back-End Technology Enumeration",
        description: "An attacker can enumerate backend technologies such as the web server, application framework, or database version. This information can be used to tailor specific exploits against known vulnerabilities in those technologies.",
        tags: ["Technology Disclosure", "Fingerprinting","Android","Dynamic"],
        comments: "",
        recommendations:"Configure the server to hide version details and technology stack information in HTTP headers and error messages."
    }
];