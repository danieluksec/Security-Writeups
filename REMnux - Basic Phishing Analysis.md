# **REMnux - Basic Phishing Analysis**

A short look at an email authentication result in a malicious .eml file (a learning sample from BTLO). I have two aims: to document my early steps with REMnux, and to better understand DMARC as a data point.

### Setup

1. Booted a REMnux VM with no network adapter enabled, so nothing in it can reach the internet.
2. Imported the BTLO sample into the VM, navigated to it and unzipped it.

### Reading the headers

An .eml file is just plain text, so to keep it simple I just pulled it open with cat instead of opening it in a mail client:

```
cat wesbite_contact_form_submission.eml
```

The line I wanted was the authentication result, added by Microsoft's mail servers when the email arrived:

```
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none; dkim=none; arc=none
```

### Focusing on DMARC

I really just want to focus on DMARC, which is an important finding because I understand it's the only one of these checks that looks at the domain the recipient actually sees in the From address, which is often a critical part of phishing.

In simple terms, DMARC is a policy the sending domain publishes. It asks whether the email passed SPF or DKIM for that same From domain, and tells receivers what to do if it didn't: let it through, quarantine, or reject.

Here the result is `dmarc=none`. This means the From domain publishes no DMARC policy at all. So:

- Nothing confirms the email really came from the domain it claims.
- Nothing from the domain owner tells receivers to quarantine or reject it if someone fakes that domain.

My initial understanding was that "none" is worse than "fail". However, after reading more, I now see that:

- **fail** means the domain has a policy and this email broke it. That's a strong sign of spoofing, although forwarding can also cause it.
- **none** means there was no policy to check. The sender can't be verified either way.

So this visible sender can't be trusted. It’s suspicious, but on its own it isn't proof.

### What I'd check next

- Which domain is in the From address? Is it a lookalike or newly registered?
- To note: Even a DMARC pass wouldn't make it safe. Attackers can set up DMARC on their own lookalike domains.

### Learnings

How much the headers give away right away + some of the interesting aspects of one verification protocol, DMARC.
