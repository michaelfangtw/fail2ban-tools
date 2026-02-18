sudo firewall-cmd --permanent --zone=drop --remove-source=134.199.156.0/24
for src in $(sudo firewall-cmd --permanent --zone=drop --list-sources); do
    sudo firewall-cmd --permanent --zone=drop --remove-source=$src
done
sudo firewall-cmd --reload


