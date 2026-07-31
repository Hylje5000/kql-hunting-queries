# 🕵🏻‍♂️ ClearFake - Hunting Queries by Miska Kytö

CLEARFAKE is a malicious in-browser JavaScript framework deployed on compromised webpages as part of campaigns to infect computers with malware. Usually these attacks are done through a ClickFix-attack, where the malicious JavaScript framework presents the end user with a fake CAPTCHA-field, prompting the user to run a command on their machine, that gets automatically inserted into their clipboard. These hunting queries can be used to hunt for ClearFake and other ClickFix malware in your environment:

- [Suspicious Process Runs](ClearFake_ProcessEvents.md)
- [Win+R Command Runs](ClearFake_RunMRU.md)