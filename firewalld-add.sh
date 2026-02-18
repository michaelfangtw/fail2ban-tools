# 減少 SYN 失敗後的重試次數 (從預設 5-6 次減到 1 次)
sudo sysctl -w net.ipv4.tcp_syn_retries=1
sudo sysctl -w net.ipv4.tcp_synack_retries=1
# 縮短 TCP Keepalive 時間
sudo sysctl -w net.ipv4.tcp_keepalive_time=600

# 封鎖 57.141.16.x (法國電信網段)
sudo firewall-cmd --permanent --zone=drop --add-source=57.141.16.0/24

# 封鎖 110.249.201.x (中國聯通網段)
sudo firewall-cmd --permanent --zone=drop --add-source=110.249.201.0/24
# 1. 封鎖新的中國聯通網段 (110.249.202.x)
sudo firewall-cmd --permanent --zone=drop --add-source=110.249.202.0/24

# 2. 封鎖另一個中國聯通攻擊網段 (111.225.149.x)
sudo firewall-cmd --permanent --zone=drop --add-source=111.225.149.0/24

# 3. 封鎖阿里雲攻擊網段 (47.128.x.x) - 直接封鎖整個 B Class
sudo firewall-cmd --permanent --zone=drop --add-source=47.128.0.0/16
sudo firewall-cmd --permanent --zone=drop --add-source=45.232.0.0/16

# Wowrack
sudo firewall-cmd --zone=drop --add-source=216.244.66.0/24 --permanent


# 4. 重新載入防火牆設定 (務必執行！)

sudo firewall-cmd --reload

sudo firewall-cmd --zone=drop --list-sources
