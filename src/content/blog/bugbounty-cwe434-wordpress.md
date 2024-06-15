---
author: arete
pubDatetime: 2024-02-12T00:00:00Z
modDatetime:
title: Bug Bounty - CWE-434 and visible WordPress directories
featured: false
draft: false
tags:
  - bugbounty
description: Bug Bounty on a private target. Discovered visible WordPress directories and files, as well as unrestricted upload of dangerous files.
---

## Introduction

For a university project, I was challenged to do Bug Bounty on a private target. While I did not make any significant discoveries, it was definitely a good starting point in Bug Bounty, which allowed me to apply my skills in a real-word setting. I will exclude some details from the original report and focus on my findings.

The target had various domains in their scope. Their primary domain was an online shop, which I will not cover here. They also had a forum and a blog domain.

## Unrestricted upload of dangerous files 

After some digging in the forum domain, I decided to focus on the upload functionality of the website. I could change my profile picture, but this forced me to resize the image, which would break any payloads. Instead, I could add pictures to a forum post. The server only allowed `.jpg`, `.png`, `.gif` and `.jpeg`, however, I quickly realized that it was only checking the file extension, and not the file content.
I started by uploading a file with a PHP payload, with valid PNG header bytes. The server returned a `200` status code when uploading.

![](@assets/images/bb1.png)

But when trying to access the file, I got a `404`.

![](@assets/images/bb2.png)

Next, I uploaded a valid JPEG file with a PHP payload embeded in a EXIF comment. It was successful and I could access the file, but the payload was not executing.

![](@assets/images/bb3.png)

I played around for a while, with other techniques, but no success.
Nonetheless, the lack of verification of the uploaded content poses a significant risk. An attacker could use the target's website as a "free" hosting service, by storing and distributing malicious files through a legitimate-looking domain, instead of a random, suspicious one. This aligns with CWE-434 (Unrestricted Upload of File with Dangerous Type).

To demonstrate this, I created a simply payload that would open the calculator application.

![](@assets/images/bb4.png)

Then I uploaded it to the target and accessed it.

![](@assets/images/bb5.png)

Lastly, I added valid JPG image headers to the EICAR test file (harmless malware) and uploaded it.

![](@assets/images/bb6.png)

Then, I proceeded to access it and scan the downloaded file with VirusTotal, which flagged it as malicious. This proved that the target could be used to host malicious files without suspicion.

![](@assets/images/bb7.png)

I submitted a report with this information, and it was leter closed as informative.

## Exposed directories and files

Next, I explored the blog. It was easy to discover that it was using WordPress and, just by typing `/wp-content/uploads`, I discovered it was accessible. 

![](@assets/images/bb8.png)

I started digging for confidential or important files, but didn't find up. Some paths, such as `/wp-content` and `/wp-content/uploads/backup`, just returned completely empty responses, despite showing a `200` status code. However, looking through `/wp-json`, I noticed that `/wp-json/wp/v2/users` and `/wp-json/wp/v2/comments` were accessible, which allowed unauthenticated users to learn user informations.

Not managing to escalate this, but thinking this was enough for a report, I decided to submit it. It was marked as duplicate.

## A final try

While exploring the blog domain, I discovered that XML-RPC was enabled, via `/xmlrpc.php`. In essence, if this was enabled and I managed to find the correct credentials, I could potentially upload a file. To verify this, I called the `system.listMethods` method.

![](@assets/images/bb9.png)

I grabbed the [xmlrpc-bruteforcer](https://github.com/aress31/xmlrpc-bruteforcer) tool, which allowed me to try up to 1999 different credentials in the same request. 

I quickly modified it to include a delay between each request, to avoid getting blocked. Then, using the usernames found in `/wp-json/wp/v2/users`, along the "admin" username, and the `rockyou` wordlist, I left it run for a while. However, it was unsuccessful, even after trying different wordlists. 

Nonetheless, I think this could possibly be an entry point.
