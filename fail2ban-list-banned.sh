for jail in $(fail2ban-client status | grep "Jail list:" | sed 's/.*Jail list://;s/,//g'); do echo "監獄 [$jail]:"; fail2ban-client status $jail | grep "IP list"; done
