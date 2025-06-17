## Problem Description  
The `ein-pfund-mails` challenge is a _baby_ rated challenge in the Misc
category for KitCTFCTF 2022. The title _ein pfund mails_ is actually German
for _"A pound of mail"_. Which makes sense since we are given an archive
(`mails.tar.gz`) containing 3993 `.eml` files. We're told one of these leaked
email files contains our flag, but we're unable to determine which file
contains the correct flag.

## Analysis  
First off, let's take a look at one of the email files.  
```  
Return-Path: <[email protected]>  
Delivered-To: [email protected]  
Received: from mail.mawalabs.de ([fd4d:6169:6c63:6f77::e])  
	by a0818493a1af with LMTP  
	id Oa/3IrxGq2JiaTIAoqc0QA  
	(envelope-from <[email protected]>)  
	for <[email protected]>; Thu, 16 Jun 2022 17:05:32 +0200  
Received: from mail-pj1-f42.google.com (mail-pj1-f42.google.com
[209.85.216.42])  
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)  
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)  
	(No client certificate requested)  
	by mail.mawalabs.de (Postcow) with ESMTPS id 5BA84A2171  
	for <[email protected]>; Thu, 16 Jun 2022 17:05:27 +0200 (CEST)  
Received: by mail-pj1-f42.google.com with SMTP id
k12-20020a17090a404c00b001eaabc1fe5dso2079659pjg.1  
       for <[email protected]>; Thu, 16 Jun 2022 08:05:27 -0700 (PDT)  
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;  
       d=gmail.com; s=20210112;  
       h=mime-version:from:date:message-id:subject:to;  
       bh=Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk=;  
       b=R1TrM58fPxWGqqUpauME4wQbljhoUlMEpPpf2NWBP1Hy8WrZH0MMkrqurXHAMNNx/H  
        I3QHbOEeHm8GjQ9GbUWHWTYt8oFutzcBiCN8+5xFbuuDoYgxyAQWpbuKcWM3h3LpkFbC  
        IN4ps9rF3ANb/DOTxYFf0TUGvTOSqXuwe1UBFnOwckfUFVwvh/FYPDzOvGiXE683jxXq  
        4GrAKzDDdbyyeKzUSyeV4ndqkTGGODLWULrUbBT/ihyNq5Nomc5QCiw61UIflwVndFdE  
        h1ufkxX2FEUJ2fpS9KbV8mfEqN+roncsHzXvVdo+ersxg4jQXA/aYOf9XoaPz48Sb9qf  
        MsMg==  
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;  
       d=1e100.net; s=20210112;  
       h=x-gm-message-state:mime-version:from:date:message-id:subject:to;  
       bh=Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk=;  
       b=AwM4jiAdlpSKBy7IZ3nfQsHnYeQp1gvVpI/Bpnoer/mkdv75drjydquL+ZXUmOaySW  
        k9jKtb/haWXRx6TCvoAFrO/ZN2tmDknI7r9yoKWdLP37Er4thOhniv0mKAPBeL47i/95  
        GG3Kfu4eMuNx/NzhqxKPIPb6Mc+tGAfe2VisvxOk/l5vbR8U4bWNiBwmF9Q4kLyFYMnb  
        gPx1ZhsxQWqFIn+hr6D9vUFxiz5cAe0m2Bq6V4e24akQrLjMrBjwY94vXzZJlb4VW6cG  
        2pffywU5CDks4qLPYnI1bkImrQJrOR3KEZSYppSm3vkBSvgJ06aTzvGRrLE18Hwmtxmv  
        5Vnw==  
X-Gm-Message-State: AJIora9DCvU5UatGInjShXcoDXp0abItZgRUoXxhwA+0+fDgg4Jv+3l8  
	jr6KvtgQZpxKkN+zFS/vejX8L1MA57H5+1ZjOis2QxR6//w=  
X-Google-Smtp-Source:
AGRyM1tXZeDE5/ppkeaIx2YE297NIvPpikDXV+2nwHlgPl646MSCkIdSwtEBFkznNZNqV1uMfJsEq98wjv3m/KYd3Vc=  
X-Received: by 2002:a17:903:244a:b0:164:2880:4df1 with SMTP id  
l10-20020a170903244a00b0016428804df1mr5108675pls.120.1655391924792; Thu, 16  
Jun 2022 08:05:24 -0700 (PDT)  
MIME-Version: 1.0  
From: Martin Wagner <[email protected]>  
Date: Thu, 16 Jun 2022 17:05:13 +0200  
Message-ID:
<CAA2ev=GHMZn2+6vgHv9kEQV5h4ZWcOapubMOJtg2BTM7VsgOAw@mail.gmail.com>  
Subject: Flag  
To: [email protected]  
Content-Type: multipart/alternative; boundary="000000000000a433c905e191f775"  
ARC-Seal: i=1; s=dkim; d=mawalabs.de; t=1655391927; a=rsa-sha256; cv=none;  
	b=qiV2rtXrZGucJcxohmzBoIzrGijMaDnXMKViSQCoub6PgUBRu9dXIo2JbqjIvVG3RiAsB5  
	x2y79l2rnSzipM62UfVfdnv7/bHXC0oxlHtIqYVDK/NqOBasDYzkgkmkAmUFIeyh7qcJ8A  
	i50585Fm1I58zMYi88Nnlq4Ou+whuc8=  
ARC-Authentication-Results: i=1;  
mail.mawalabs.de;  
	dkim=pass header.d=gmail.com header.s=20210112 header.b=R1TrM58f;  
	spf=pass (mail.mawalabs.de: domain of [email protected] designates 209.85.216.42 as permitted sender) [email protected];  
	dmarc=pass (policy=none) header.from=gmail.com  
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=mawalabs.de;  
	s=dkim; t=1655391927;  
	h=from:from:reply-to:subject:subject:date:date:message-id:message-id:  
	 to:to:cc:mime-version:mime-version:content-type:content-type:  
	 dkim-signature; bh=Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk=;  
	b=oiuiewyUJBkwDRfqclseGFj1hYEfF0kN+UD7pdWf/wun/Sccb1T9bP6a9DGS/liipuXPhS  
	DayxqKgsuRqvB5c1WSxQXIc2iXdKkTttQt1LgaXE1d+wSo6Hap502RMji4aZVcMM6owh/T  
	1fhY0QCzzNrw2JCYoeMCtcZ0LNWvtTY=  
X-Last-TLS-Session-Version: TLSv1.3  
Authentication-Results: mail.mawalabs.de;  
	dkim=pass header.d=gmail.com header.s=20210112 header.b=R1TrM58f;  
	spf=pass (mail.mawalabs.de: domain of [email protected] designates 209.85.216.42 as permitted sender) [email protected];  
	dmarc=pass (policy=none) header.from=gmail.com  
X-Spamd-Result: default: False [1.79 / 15.00];  
	RBL_SORBS_RECENT(2.00)[209.85.216.42:from];  
	BAD_REP_POLICIES(2.00)[];  
	NEURAL_HAM_SHORT(-2.00)[-1.000];  
	MIME_GOOD(-0.10)[multipart/alternative,text/plain];  
	RWL_MAILSPIKE_GOOD(-0.10)[209.85.216.42:from];  
	MX_GOOD(-0.01)[];  
	IP_REPUTATION_HAM(-0.00)[asn: 15169(0.00), country: US(-0.00), ip: 209.85.216.42(0.00)];  
	FROM_HAS_DN(0.00)[];  
	R_DKIM_ALLOW(0.00)[gmail.com:s=20210112];  
	BCC(0.00)[];  
	DWL_DNSWL_NONE(0.00)[gmail.com:dkim];  
	TO_MATCH_ENVRCPT_ALL(0.00)[];  
	RCPT_COUNT_ONE(0.00)[1];  
	ARC_NA(0.00)[];  
	CLAM_VIRUS_FAIL(0.00)[failed to scan and retransmits exceed];  
	PREVIOUSLY_DELIVERED(0.00)[[email protected]];  
	RCPT_MAILCOW_DOMAIN(0.00)[mawalabs.de];  
	FREEMAIL_ENVFROM(0.00)[gmail.com];  
	RCVD_IN_DNSWL_NONE(0.00)[209.85.216.42:from];  
	ARC_SIGNED(0.00)[mawalabs.de:s=dkim:i=1];  
	R_SPF_ALLOW(0.00)[+ip4:209.85.128.0/17];  
	TO_DN_NONE(0.00)[];  
	FREEMAIL_FROM(0.00)[gmail.com];  
	ASN(0.00)[asn:15169, ipnet:209.85.128.0/17, country:US];  
	MID_RHS_MATCH_FROMTLD(0.00)[];  
	DMARC_POLICY_ALLOW(0.00)[gmail.com,none];  
	MIME_TRACE(0.00)[0:+,1:+,2:~];  
	DKIM_TRACE(0.00)[gmail.com:+];  
	RCVD_TLS_LAST(0.00)[];  
	FROM_EQ_ENVFROM(0.00)[];  
	RCVD_COUNT_TWO(0.00)[2]  
X-Rspamd-Queue-Id: 5BA84A2171

--000000000000a433c905e191f775  
Content-Type: text/plain; charset="UTF-8"

Hi,

die Flag ist KCTF{1d2fa1ed91a0310dad83242abc3f8a92}

LG  
Martin

--000000000000a433c905e191f775  
Content-Type: text/html; charset="UTF-8"

<div dir="ltr">Hi,<div>  
</div><div>die Flag ist KCTF{1d2fa1ed91a0310dad83242abc3f8a92}</div><div>  
</div><div>LG</div><div>Martin</div></div>

--000000000000a433c905e191f775--  
```

Of note, are several _signatures_ and a possible flag
(`KCTF{1d2fa1ed91a0310dad83242abc3f8a92}`).

If we take a `diff` of the two different emails (e.g. `diff fffc5.eml
ffdef.eml`), only the flag is changed.  
```diff  
110c110  
< die Flag ist KCTF{1d2fa1ed91a0310dad83242abc3f8a92}  
---  
> die Flag ist KCTF{a3afe0043bf7736216bc7ace6efac886}  
118c118  
< <div dir="ltr">Hi,<div>  
</div><div>die Flag ist KCTF{1d2fa1ed91a0310dad83242abc3f8a92}</div><div>  
</div><div>LG</div><div>Martin</div></div>  
---  
> <div dir="ltr">Hi,<div>  
</div><div>die Flag ist KCTF{a3afe0043bf7736216bc7ace6efac886}</div><div>  
</div><div>LG</div><div>Martin</div></div>  
```

This confirms what the prompt told us, so we can't identify the correct flag
by any differences between the files. Instead we'll have to utilize the
signatures provided in the emails to verify a valid `.eml`.

## Solution  
The first signature we see in the file is a `DKIM-Signature`. There is a
useful [explainer](https://mailtrap.io/blog/dkim/) over on mailtrap[.]com, if
you want to get into the nitty gritty, but the short of it is that DKIM is a
common signature type that's used to verify the sender and __content__ of an
email have not been altered. That should be perfect to find the original,
unaltered email in our _ein pfund mails_.

Luckily, there are several DKIM verification libraries available on
[PyPI](https://pypi.org/search/?q=dkim). I chose [check-
dkim](https://pypi.org/project/check-dkim/) since it was at the top of the
list for my search. In the case of `check-dkim`, it's actually a CLI script.
So, after installing (`pip install check-dkim`), we can verify that it works
for one of our `.eml` files.  
```console  
$ check-dkim mail/fffc5.eml  
Error verifying DKIM  
body hash mismatch (got b'SHy1AAdR/+J5fTOT5HqeEr23p+JmXnlXWdr1QxcFqcU=',
expected b'Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk=')  
```

Now let's write a simple bash script to verify every email file.  
```bash  
#!/bin/bash  
# dkim_verify.sh  
find "$1" -iname *.eml -type f -exec echo -ne "FILE: {} --- " \; -exec check-
dkim {} \;  
```

Execute the script to start checking.  
```bash  
./dkim_verify.sh ./mail/  
```

Here is the output from our first few files.  
```  
FILE: mail/c9f01.eml --- Error verifying DKIM  
body hash mismatch (got b'KSjh/SWf9CoOfANlP1JwziULd7TJwo2jAXdS6WxxiXk=',
expected b'Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk=')  
FILE: mail/483c0.eml --- Error verifying DKIM  
body hash mismatch (got b'NPfXTjlgeHmYX3XL505Y9ZlDsWR/nKofQRnlX2Eg+Vk=',
expected b'Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk=')  
FILE: mail/e1262.eml --- Error verifying DKIM  
body hash mismatch (got b'IwEUYGwkRHvyIUocHDTn1mq653UyllFukFAsC7/bewY=',
expected b'Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk=')  
FILE: mail/a9331.eml --- Error verifying DKIM  
body hash mismatch (got b'2kwfDpgExCVsPaquMn2PMAqKf/UEuOQneY6YpVutQ+U=',
expected b'Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk=')  
FILE: mail/c65c1.eml --- Error verifying DKIM  
body hash mismatch (got b'GGvQpfeY8Vzvfms3TWn1TsYW2Ws4CKhenm26CVZ7kCs=',
expected b'Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk=')  
```  
----

After a few minutes we get a hit. Here is the output leading up to the valid
`.eml`.  
```  
FILE: mail/3c586.eml --- Error verifying DKIM  
body hash mismatch (got b'DopvYFdcPVYCj2nGEr3Jdll+EK7xiVVk33K/6xRJp90=',
expected b'Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk=')  
FILE: mail/06570.eml --- Error verifying DKIM  
body hash mismatch (got b'uJ/mmb0346p2GMzAqGnz/6hn5G0cL/jiotY2dl2tBJk=',
expected b'Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk=')  
FILE: mail/438b5.eml --- DKIM verified successfully  
```

Now we can check which flag is in `438b5.eml`.  
```  
grep -oP "(KCTF{.*})" mail/438b5.eml  
KCTF{1f8e659e892f2b2a05a54b8448ccbff9}  
KCTF{1f8e659e892f2b2a05a54b8448ccbff9}  
```  
Here we have our flag! `KCTF{1f8e659e892f2b2a05a54b8448ccbff9}`  

Original writeup (https://www.cblanken.dev/posts/einpfundmails/).