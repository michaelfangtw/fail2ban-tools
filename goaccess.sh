sudo tail -n 500000 /var/log/httpd/access_log | grep -v "::1" | goaccess - --log-format=COMBINED -a
