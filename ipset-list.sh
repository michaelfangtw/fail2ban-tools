# 查看所有封鎖集合的名稱
sudo ipset list -n

# 查看特定集合（例如 apache-combined）裡面有哪些網段
sudo ipset list f2b-apache-scan-error

sudo ipset list f2b-apache-combined
sudo ipset list f2b-apache-wp-bruteforce

