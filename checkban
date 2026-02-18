#!/bin/bash
# ---------------------------------------------------------
# Fail2ban + Firewalld 戰情儀表板 (進階罪證版)
# ---------------------------------------------------------

# 自動尋找 Web Log 位置
LOG_FILES="/var/log/httpd/access_log*"

get_country_name() {
    local target=$1
    local pure_ip=$(echo $target | cut -d'/' -f1)
    local geo_all=$(geoiplookup "$pure_ip")
    local code=$(echo "$geo_all" | grep -v "ASNum" | sed 's/GeoIP//g' | grep -oE '[A-Z]{2}' | head -n 1)
    local isp=$(echo "$geo_all" | grep "ASNum" | awk -F': ' '{print $2}' | tr -d '\n')

    if [[ -z "$code" || "$geo_all" == *"not found"* ]]; then
        echo "未知 (Unknown)"
    else
        [[ "$code" == "IP" ]] && code="TW" 
        echo "$code | $isp"
    fi
}

get_attack_evidence() {
    local target=$1
    # 支援 CIDR 格式，提取主段
    local search_pattern=$(echo $target | cut -d'/' -f1 | sed 's/\.0$//')
    
    # 1. 統計總存取次數
    local total=$(grep -ch "$search_pattern" $LOG_FILES 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
    
    if [ "$total" -eq 0 ]; then
        echo "Log 無紀錄"
    else
        # 2. 偵測 SQL 注入特徵數量
        local sqli=$(grep -h "$search_pattern" $LOG_FILES 2>/dev/null | grep -Ei "UNION|SELECT|XMLType|CHR\(|CASE.*WHEN" | wc -l)
        
        # 3. 【新增】列出最常嘗試的攻擊路徑 (取前 3 名)
        # 這裡會過濾掉正常的資源請求，抓取路徑，排序並計算次數
        local paths=$(grep -h "$search_pattern" $LOG_FILES 2>/dev/null | \
                      awk -F'\"' '{print $2}' | awk '{print $2}' | \
                      grep -vE "\.(jpg|jpeg|png|gif|css|js|ico)$" | \
                      sort | uniq -c | sort -nr | head -n 3 | \
                      awk '{print $2 "("$1"次)"}' | tr '\n' ' ')

        echo -e "共存取 ${total} 次 | \033[1;31mSQLi: ${sqli}\033[0m"
        echo -e "      \033[1;36m└─ 關鍵路徑:\033[0m ${paths:-"無明顯路徑紀錄"}"
    fi
}

echo -e "\n\033[1;34m=== [ 1. 系統效能負載 ] ===\033[0m"
uptime
echo ""

echo -e "\033[1;35m=== [ 2. Firewalld 永久阻擋名單 (Zone: drop) ] ===\033[0m"
sources=$(sudo firewall-cmd --zone=drop --list-sources)
for src in $sources; do
    info=$(get_country_name $src)
    echo -e "  [已阻擋] \033[1;31m$src\033[0m ($info)"
    get_attack_evidence $src
done
echo ""

echo -e "\033[1;31m=== [ 3. Fail2ban 動態監獄(配合ipset) ] ===\033[0m"
jails=$(sudo fail2ban-client status | grep "Jail list:" | sed 's/.*Jail list://;s/,//g')
for jail in $jails; do
    count=$(sudo fail2ban-client status $jail | grep "Currently banned:" | awk '{print $4}')
    [[ "$count" -eq 0 ]] && continue
    echo -e "\033[1;33m監獄 [$jail]: $count 人服刑\033[0m"
    sudo ipset list f2b-$jail 2>/dev/null | grep -E "^[0-9]" | while read line; do
        ip=$(echo $line | awk '{print $1}')
        remain=$(echo $line | awk '{print $3}')
        info=$(get_country_name $ip)
        echo -e "  - \033[1;37m$ip\033[0m ($info) [\033[0;32m剩餘 ${remain}s\033[0m]"
        get_attack_evidence $ip
    done
done
echo -e "\n"
