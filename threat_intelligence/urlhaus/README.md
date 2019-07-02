This Threat Intelligence module can be used to submit URLs to the URLhaus database. Please read the submission policy before using this module.

Important: this module does not perform lookups into the URLhaus database. This should be done with another Threat Intelligence module, such as Yeti, with a URLhaus feed.

# Submission Policy

URLhaus is currently only collecting websites (URLs) that are directly being used to distribute malware. Please note that any other submissions will be ignored / deleted from URLhaus.
Before you start to submit URLs to URLhaus, I encourage you to read the following submission policy:

 - Active malware distribution sites: Please ensure that you only submit active (online) malware distribution sites that are currently serving a payload (please see the definition of payload below). Malware URLs that are down and / or have already been cleaned should not be submitted to URLhaus.
 - Payload: A payload can be any file (executable, script, document) that harms or infect a computer once downloaded and executed. Some examples: Windows executables, Office documents, PowerShell scripts, Bash scripts, hta, ELF.
 - URL shorteners: Any URL submitted to URLhaus must host an active malware payload. Redirection sites or URL shorteners (e.g. bit.ly) that are just used for redirection and that are not hosting any payload should not be submitted to URLhaus.
 - Adware is not Malware: Unlike Malware, most common Adware (aka Potential Unwanted Programs - PUPs) do need some sort of user interaction. In many cases, they also come with a licences agreement that the user has to accept and that is more or less transparent with regads to what the Adware does. Please refrain from submitting URLs to URLhaus that are distributing Adware.
 - Phishing and Phishing kits: Phishing sites or websites that are hosting a phishing kit should not be submitted to URLhaus (Phishing is not Malware). If you would like to report phishing websites, you may want to report them to AWPG, PhishTank or Netcraft.
 - Automated submissions: Should you decide to make automated submissions to the URLhaus API, please ensure that your script has implemented proper URL verification. Please also ensure that you do not submit any private IP addresses (RFC1597) or any IP addresses that are used for any other special purpose (RFC6890).
 - Exploit kits: Websites that are hosting an exploit kit should not be submitted to URLhaus unless the submitted URL serves the final payload.
 - Geo IP filter: Some malware distribution sites may use a Geo IP filter to restrict the download of the payload to a specific country. You can tell URLhaus about this restriction by using the tag geofenced and a tag with the three letter NATO country code (e.g. GBR for Great Britain). URLhaus will then try to fetch the payload using an IP address from the specified Geo location.
 - Duplicates: To avoid duplicates and ensure that the malware sites tracked by URLhaus can be properly used as IOC, please make sure that you submit URLs to URLhaus as you see them on the wire, returing HTTP 200 OK. For example, http://evil.tld/91BOYI/oamo/US would become http://easterbrookhauling.com/91BOYI/oamo/US/ (note the tailing /) and https://evil.tld?thisisbad=1 would become https://evil.tld/?thisisbad=1 (note / after .tld).

Note: Should you repeatedly violate the submission policy documented above, your account may get banned from URLhaus.
