The AI-BOLIT scanner The AI-BOLIT scanner is designed to check the site for viruses and hacking. It can be used both as a preventive measure to regularly check the site for a virus, and to search for hacker shells, backdoors, phishing pages, viral inserts, doorways, spam links and other malicious fragments in the site files.

Scanning can be performed either directly on the hosting (it is recommended to run the scanner in command line mode via SSH) or on a local computer under any operating system (Windows, MacOS X, *nix). The AI-BOLIT scanner checks files against its own anti-virus database, and also uses special heuristics to detect new (still unknown) malicious fragments. If dangerous fragments are detected, it generates a report with a list of detected files in html or text format.

The scanner has two operating modes "normal" and "paranoid".

To diagnose hacking and infection of the site, it is enough to check the site files in the usual mode. It does not give false positives and is suitable for assessing whether a site is infected or hacked. In order to check the site for viruses and hacker scripts in detail, as well as to generate a report for disinfecting the site, it is necessary to scan the files in the "paranoid" mode. This report includes not only known virus fragments or hacker scripts, but also suspicious fragments that need to be studied, as they could potentially be malicious.

Sometimes the same code snippets can be used in both hacker scripts and legitimate CMS scripts. Therefore, in automatic mode, it is impossible to determine 100% whether a file is malicious. This file will be displayed in the report and it is necessary to manually determine its danger.

--

Remember that one missed shell or backdoor is enough for a second hack and infection to occur.
site, so when disinfecting the site, use the report generated in the "paranoid" mode and check all files marked
red in the report.

Starting the scanner:

```php ai-bolit.php --path=PATH_TO_FOLDER_SITE```

If you run the scanner in command line mode, then the mode number can be specified via the --mode parameter.

`php ai-bolit.php --mode=1 is a normal mode check (diagnostics)`

`php ai-bolit.php --mode=2 is paranoid mode check (for cure)`




Express check (not recommended for website treatment):
--------------------------------

1. in the file /ai-bolit/ai-bolit.php find the line
define('PASS', '....

Enter the password in the second apostrophes, for example Mypass16.

define('PASS', 'MyPass234');

2. copy files from the /ai-bolit/ folder to the server in the root directory

3. open https://your_site/ai-bolit.php?p=MyPass234 in a browser and wait for the report

4. after displaying the report, delete the files from AI-BOLIT and the script itself from the site



Full check (recommended):
--------------------------------

1. copy files from the /ai-bolit/ folder to the server in the root directory

2. connect to the server via ssh, go to the site folder

3. run the command on the command line
    php ai-bolit.php

4. wait for the scan to finish

5. copy the AI-BOLIT-REPORT-<date>-<time>.html file from the serveris designed to check the site for viruses and hacking.
