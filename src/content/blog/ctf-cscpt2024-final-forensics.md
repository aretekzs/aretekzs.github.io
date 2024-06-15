---
author: arete
pubDatetime: 2024-06-03T00:00:00Z
modDatetime:
title: CTF - CSCPT 2024 Final - Encrypted Filesystem Writeup - Forensics
featured: false
draft: false
tags:
  - ctf
  - forensics
description: A compressed archive file was given, and the description stated that it contained a suspicious USB filesystem, which was encrypted, along with some Windows registry files.
---

## Introduction

This challenge was presented at the CSCPT 2024 Final. A compressed archive file was given,  and the description stated that it contained a suspicious USB filesystem, which was encrypted, along with some Windows registry files. It also stated that the system user (CSCPT) is known to reuse passwords, typically following a pattern: one uppercase letter, five lowercase letters, and three digits.

## Finding the password for the encrypted filesystem

The first step is, obviously, to extract the archive and take a quick look at its content.

```shell
$ tar -zxvf encfs.tar.gz
disk01.dd
SAM
SECURITY
SYSTEM
```

```shell
$ file disk01.dd SAM SECURITY SYSTEM
disk01.dd:    DOS/MBR boot sector MS-MBR Windows 7 english at offset 0x163 "Invalid partition table" at offset 0x17b "Error loading operating system" at offset 0x19a "Missing operating system"; partition 1 : ID=0xee, start-CHS (0x0,0,2), end-CHS (0x81,254,63), startsector 1, 4294967295 sectors
SAM:          MS Windows registry file, NT/2000 or above
SECURITY:     MS Windows registry file, NT/2000 or above
SYSTEM:       MS Windows registry file, NT/2000 or above
```

As mentioned, the filesystem is encrypted, and the first goal is to find the password. To do this, the given registry files come in handy. These files belong to the SAM hive (Security Account Manager), where credentials and account information are stored. The passwords are usually hashed as NT hashes and located within the SAM file. However, to prevent unauthorized access, the SAM file is encrypted with a SysKey. This SysKey can be extracted from the SYSTEM registry and, since I have both, I can try to leak the password hash.

After some searching, I found the `sampdump2` tool, which is designed to dump passwords hashes in scenarios like this.

```shell
$ samdump2 -o hashes.txt ./SYSTEM ./SAM && cat hashes.txt
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Admin:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CSCPT:1002:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

It works and I get the hash of the desired user (CSCPT). So, now I need to crack it according to the given patterns. To do this, I use `hashcat`, which allows me to specify the desired pattern. I also need to specify the attack mode (brute-force) and the hash type (NTLM).

```shell
$ tail -n 1 hashes.txt > hash
$ hashcat -a 3 -m 1000 -o cracked-hash.txt hash "?u?l?l?l?l?l?d?d?d"
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 31d6cfe0d16ae931b73c59d7e0c089c0
Time.Started.....: Thu Jun  6 19:18:56 2024 (3 mins, 8 secs)
Time.Estimated...: Thu Jun  6 19:22:04 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: ?u?l?l?l?l?l?d?d?d [9]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1038.0 MH/s (0.45ms) @ Accel:512 Loops:128 Thr:64 Vec:1
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 308915776000/308915776000 (100.00%)
Rejected.........: 0/308915776000 (0.00%)
Restore.Point....: 17576000/17576000 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:17536-17576 Iteration:0-128
Candidate.Engine.: Device Generator
Candidates.#1....: Gxqfkj573 -> Xqxqxq649
Hardware.Mon.#1..: Temp: 80c Util: 80% Core:1657MHz Mem:3504MHz Bus:4
```

However, the password was not recovered, which is weird since I seem to be on the right path. I decided to contact the challenge authors, which confirmed that the password hash I possessed was not the correct one. After this, they release a hint stating that, if someone retrieve the `31d6cfe0d16ae931b73c59d7e0c089c0` hash, it was most likely due to a malfunction of the dump program. So, I obviously decided to try a different program, `impacket`.

```shell
$ /sbin/secretsdump.py -sam SAM -system SYSTEM local > hashes2.txt && cat hashes2.txt
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x31b139c5e8826f84c61c98e4b2e315b5
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:17c9bb6e7168ad5e10483392f3a81ca4:::
Admin:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CSCPT:1002:aad3b435b51404eeaad3b435b51404ee:49efc2542d5ee42d8c68f552632fdbcd:::
```

Let's try to crack the new hash.

```shell
$ tail -n 2 hashes2.txt | head -n 1 > hash2
$ hashcat -a 3 -m 1000 -o cracked-hash.txt hash2 "?u?l?l?l?l?l?d?d?d"
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 49efc2542d5ee42d8c68f552632fdbcd
Time.Started.....: Thu Jun  6 19:39:04 2024 (22 secs)
Time.Estimated...: Thu Jun  6 19:39:26 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: ?u?l?l?l?l?l?d?d?d [9]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1665.1 MH/s (7.05ms) @ Accel:64 Loops:256 Thr:256 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 36724015104/308915776000 (11.89%)
Rejected.........: 0/36724015104 (0.00%)
Restore.Point....: 2064384/17576000 (11.75%)
Restore.Sub.#1...: Salt:0 Amplifier:8704-8960 Iteration:0-256
Candidate.Engine.: Device Generator
Candidates.#1....: Ojhdzk432 -> Fueznn101
Hardware.Mon.#1..: Temp: 66c Util: 93% Core:1683MHz Mem:3504MHz Bus:4
```

And it quickly succeeds. The password is recovered.

```shell
$ cat cracked-hash.txt
49efc2542d5ee42d8c68f552632fdbcd:Fohqwe666
```

I can now decrypt the filesystem.

## Decrypting the filesystem

```shell
$ fdisk -l disk01.dd
Disk disk01.dd: 1 GiB, 1073741824 bytes, 2097152 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: B1284885-1F97-4BD4-AC81-7806F5F5223E

Device     Start     End Sectors  Size Type
disk01.dd1    34   32767   32734   16M Microsoft reserved
disk01.dd2 32768 2093055 2060288 1006M Microsoft basic data
```

Given that this is a Windows filesystem, it is most probably encrypted with BitLocker.

To work with the disk image as if it were a physical disk, I need to associate it with a loop device. I also need to create mappings for its partitions.

```shell
$ sudo losetup /dev/loop0 disk01.dd
$ sudo kpartx -av /dev/loop0
add map loop0p1 (254:0): 0 32734 linear 7:0 34
add map loop0p2 (254:1): 0 2060288 linear 7:0 32768
```

Next, I create a directory to mount the BitLocker volume and another for the decrypted content. I then decrypted the `loop0p2` partition, which is the one identified as `Microsoft basic data`. The `loop0p1` partition is usually a partition with no user data and reserved by Windows for system management.
Lastly, I mount the decrypt volume and I am able to access the filesystem. 

```shell
$ mkdir mnt/bitlocker mnt/decrypted
$ dislocker -V /dev/mapper/loop0p2 -uFohqwe666 -- mnt/bitlocker
$ mount -o loop mnt/bitlocker/dislocker-file mnt/decrypted
$ tree -a mnt/decrypted/
mnt/decrypted/
├── $RECYCLE.BIN
│   └── S-1-5-21-567185537-1448028262-3746335840-1002
│       └── desktop.ini
├── CSCPT.kdbx
└── System Volume Information
    ├── FVE2.{24e6f0ae-6a00-4f73-984b-75ce9942852d}
    ├── FVE2.{aff97bac-a69b-45da-aba1-2cfbce434750}.1
    ├── FVE2.{aff97bac-a69b-45da-aba1-2cfbce434750}.2
    ├── FVE2.{da392a22-cae0-4f0f-9a30-b8830385d046}
    ├── FVE2.{e40ad34d-dae9-4bc7-95bd-b16218c10f72}.1
    ├── FVE2.{e40ad34d-dae9-4bc7-95bd-b16218c10f72}.2
    ├── FVE2.{e40ad34d-dae9-4bc7-95bd-b16218c10f72}.3
    ├── IndexerVolumeGuid
    └── WPSettings.dat

4 directories, 11 files
```

## Trying to open the KeePass database

The `CSCPT.kdbx` file indicates a KeePass database, while the other directories do not seem to contain useful information (the FVE files contain metadata about the BitLocker volume). Given that the user is known to repeat passwords, I try Fohqwe666, but it does not work.

![](@assets/images/foren1.png)

So, 2 different methods came to my mind. First, I tried to extract the hash of the master password from the `.kdbx` file, so I could then attempt to crack it (using the known pattern). For this, `keepass2john` comes in hand. However, this did not seem to be the right path.

```shell
$ keepass2john mnt/decrypted/CSCPT.kdbx
! mnt/decrypted/CSCPT.kdbx : File version '40000' is currently not supported!
```

The second method was the recent CVE-2023-32784. If the database password was typed, and not copied, in the saved version, it may be possible to retrieve it thanks to a flaw in KeePass 2.X, which leaves a leftover string in memory for every character typed. So, I grabbed the [PoC from Github](https://github.com/vdohney/keepass-password-dumper) and tried it, but again, to no luck.

```shell
$ git clone https://github.com/vdohney/keepass-password-dumper && cd keepass-password-dumper
$ dotnet run ../mnt/decrypted/CSCPT.kdbx

Password candidates (character positions):
Unknown characters are displayed as "●"
1.:	●
Combined: ●
```

My final thought was to just brute-force the password, but it would just be very impratical.

## Recovering the deleted file and getting the flag

By this time the competition was over, and I decided to take a break from the computer. Nonetheless, I still wanted to solve the challenge, and the authors release another hint, saying that we should look for deleted files.
So, I run `fls` and passed the `dislocker-file` as the disk image argument, since it represents the decrypted volume. Then, I used `icat` to extract the file.

```shell
$ sudo fls -d mnt/bitlocker/dislocker-file
-/r * 50-128-1:	DELETEME.txt
$ sudo icat mnt/bitlocker/dislocker-file 50-128-1 > DELETEME.txt
$ cat DELETEME.txt
XqpBm4arY4w1V8DMnxCqYro73oJLgbcMtxe3sx9drg6Qy8uoFYckLMSwKc9ZNjWyNHoQGAfG3QDDuq7yqR8iLQpRV4z8rMm6UGZAtqw5CR7tMLmrUC7kdr68YQMQH2cWMZQaUUoaJRwRskkbC4isck9oHmsQVm4gQBP584RfcCPuFgq1PGetxn6jn9cELx8ChPr9u8HEs2akC1vGj643Gr1Jc3B8knTAvszmrKATyefQYny7ssB6Dqzm7ffxaE4q7Z9d84XAqbpunQcDAeiXsiD8JD4vs3aWFMuVVhURoSeCLW6sLCHZt9HWEfcpjSyh9FPuvUiK2
```

This looks like base64, but, when trying to decode it, it does not work. 

```shell
$ base64 -d DELETEME.txt
^�A���c�5W�̟�b�;ނK��
                   ���]���˨�$,İ)�Y65�4z��ú��"-
QW���ɺPf@��9	�0��P.�v��ag1��QJ�%�I
                                     �rOhkVn @��_p#�
�<g��~���/�����ĳf�
                  [Ə�7��Isp|�t���欠���b|���z�����hN*�]����n�藲 �$>/�v�˕V�'�-n�,!ٷ���)�,��S�H�base64: invalid input
```

Let's try to find what it is, using the magic operation in CyberChef.

![](@assets/images/foren2.png)

It claims to be base58, and sure enough, base58 correctly decodes the ciphertext. However, it is still not readable.

![](@assets/images/foren3.png)

Looks like a Caeser cipher, so let's substitute the characters.

![](@assets/images/foren4.png)

And there is the master password! I can now open the KeePass database.

![](@assets/images/foren5.png)

And the challenge is solved.

![](@assets/images/foren6.png)
