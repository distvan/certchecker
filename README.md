The CertChecker class helps to detect a domain SSL certification expiration.
It sends a notification emails when checking failed or need a cert update.

###Usage:

- Put the domain names into the domain.txt (every line should containt one domain name).
- Install dependencies running compose comand.
- Setup the config.ini file.
- Setup a cron job and run the cron_script.php (for example: every day, or every week at once)