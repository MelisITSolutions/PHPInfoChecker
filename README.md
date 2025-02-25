# PHPInfoChecker

Simple Python tool that checks possible vulnerable php functions when given a phpinfo file
inspired by the [dfunc-bypasser](https://github.com/teambi0s/dfunc-bypasser).

## Categories

The tester is split in categories,
for **CTF's** the -rce flag should be enough,
\
for **pentests** the -a flag is best suited

| Flag     | Use                                                                                               |
| -------- | ------------------------------------------------------------------------------------------------- |
| --url    | URL of PHPinfo (e.g., https://example.com/phpinfo.php)                                            |
| --file   | Local path to PHPinfo file (e.g., dir/phpinfo)                                                    |
| -a       | Check all types                                                                                   |
| -rce     | Check for possible Remote Code Execution (RCE)                                                    |
| -phpce   | Check for possible PHP code execution                                                             |
| -fd      | Check for possible file and directory manipulation                                                |
| -inf     | Check for possible information disclosure                                                         |
| -db      | Check for possible interaction with databases and external systems                                |
| -ssrf    | Check for possible interaction with remote servers, leading to SSRF (Server-Side Request Forgery) |
| -mail    | Check for possible ability to send mail                                                           |
| -privesc | Check for possible privilege escalation                                                           |
| -pt      | Check for possible path traversal                                                                 |
| -sec     | Check for possible security bypass (hashes, etc.)                                                 |
| -modules | Check for modules that can lead to interesting behavior                                           |

examples:
`python3 phpchecker.py --file ./phpinfo.html -rce`

_note: if a function is found it doesn't neccesary mean it can be exploited._
