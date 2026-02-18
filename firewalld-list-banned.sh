#!/bin/bash
# ---------------------------------------------------------
# Firewalld 阻擋名單分析 (離線 GeoIP 版)
# ---------------------------------------------------------

echo -e "\033[1;34m=== [ Firewalld 阻擋名單深度分析 ] ===\033[0m"
# 調整欄位寬度以符合中文排版
printf "\033[1;33m%-18s | %-10s | %-15s | %s\033[0m\n" "網段/IP" "國家" "封鎖時間" "罪證概要"
echo "--------------------------------------------------------------------------------"

# 撈取 drop 區域的所有來源
sources=$(sudo firewall-cmd --zone=drop --list-sources)
LOG_FILE="/var/log/httpd/access_log"
HISTORY_LOG="/var/www/fail2ban/firewalld_ban_history.log"

if [ -z "$sources" ]; then
    echo "  [提示] 目前阻擋清單是空的。"
else
    for src in $sources; do
        # 1. 提取 IP
        pure_ip=$(echo $src | cut -d'/' -f1)
        search_pattern=$(echo $pure_ip | sed 's/\.0$//')

        # 2. 離線地理資訊查詢
        geo_raw=$(geoiplookup "$pure_ip")
        if [[ "$geo_raw" == *"TW, Taiwan"* ]]; then
            c_name="台灣"
        else
            country_code=$(echo "$geo_raw" | grep "Country Edition" | awk -F': ' '{print $2}' | cut -d',' -f1)
            case "$country_code" in
                "CN") c_name="中國" ;; "US") c_name="美國" ;; "RU") c_name="俄羅斯" ;;
                "AR") c_name="阿根廷" ;; "SG") c_name="新加坡" ;; "HK") c_name="香港" ;;
                "DE") c_name="德國" ;; "FR") c_name="法國" ;; "IP Address not found") c_name="未知" ;;
                *) c_name="${country_code:-未知}" ;;
            esac
        fi

        # 3. 抓取封鎖時間 (優先從你的自建日誌抓)
        ban_time=""
        if [ -f "$HISTORY_LOG" ]; then
            ban_time=$(grep "$src" "$HISTORY_LOG" | tail -n 1 | awk '{print $1,$2,$3}')
        fi
        [[ -z "$ban_time" ]] && ban_time="歷史久遠"

        # 4. 抓取罪證概要 (Log 存取次數與是否有 SQLi)
        total_hits=$(grep -c "$search_pattern" "$LOG_FILE")
        sqli_hits=$(grep "$search_pattern" "$LOG_FILE" | grep -Ei "UNION|SELECT|OR.*1=1" | wc -l)
        
        evidence="存取:${total_hits}次"
        if [ "$sqli_hits" -gt 0 ]; then
            evidence="${evidence} (含 SQLi:${sqli_hits})"
        fi

        # 5. 格式化輸出
        printf " \033[1;31m%-17s\033[0m | %-8s | %-14s | %s\n" "$src" "$c_name" "$ban_time" "$evidence"
    done
fi
echo "--------------------------------------------------------------------------------"