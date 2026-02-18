#!/bin/bash
# ---------------------------------------------------------------------
# 伺服器安全掃描預報腳本 (v3.1 - 環境自適應修復版)
# ---------------------------------------------------------------------

# --- [ 1. 環境初始化與語系修正 ] ---
export LANG=en_US.UTF-8  # 強制英文語系，確保對齊 Apache 的 Feb 格式
TODAY_STR=$(date "+%d/%b/%Y")

# 自動偵測今天最有價值的 Log (解決 180MB 檔案在舊檔的問題)
LOG_FILE=$(ls -S /var/log/httpd/access_log* | head -n 1)
SUSPECT_FILE="/tmp/ip-suspect.txt"
FINAL_REPORT="/tmp/daily_attack_report.txt"
BAN_LOG="/var/www/fail2ban/firewalld_ban_history.log"

# --- [ 2. 白名單設定 ] ---
WHITELIST=("124.218.27.177" "127.0.0.1" "::1")
EXCLUDE_REGEX=$(echo "${WHITELIST[@]}" | sed 's/ /|/g' | sed 's/\./\\./g')

# --- [ 3. 快速封鎖模式 (--block) ] ---
if [[ "$1" == "--block" ]]; then
    echo -e "\033[1;33m=== [ 執行快速封鎖模式 ] ===\033[0m"
    [ ! -s "$SUSPECT_FILE" ] && echo "錯誤: 無待封鎖清單。" && exit 1
    sort -u "$SUSPECT_FILE" | while read subnet; do
        [[ -z "$subnet" || "$subnet" == "66.249."* ]] && continue
        sudo firewall-cmd --zone=drop --add-source="$subnet" --permanent > /dev/null 2>&1
        sudo firewall-cmd --reload > /dev/null 2>&1
        echo "$(date) - Blocked: $subnet" >> "$BAN_LOG"
        echo -e " [\033[0;31mDONE\033[0m] 已永久封鎖: $subnet"
    done
    > "$SUSPECT_FILE"
    exit 0
fi

# --- [ 4. 深度分析模式 ] ---
# 建立今日臨時日誌，加速分析
grep "$TODAY_STR" "$LOG_FILE" > /tmp/today_working.log
[ ! -s /tmp/today_working.log ] && cp "$LOG_FILE" /tmp/today_working.log # 萬一今日沒紀錄，分析最大檔案

log_size=$(du -h /tmp/today_working.log | cut -f1)
log_lines=$(wc -l < /tmp/today_working.log)

echo -e "\033[0;34m=== [ 深度分析啟動 ] ===\033[0m"
echo "Log 來源: $(basename $LOG_FILE) | 大小: $log_size ($log_lines 行)"
echo "---------------------------------------------------------"

> "$SUSPECT_FILE"
echo "=== 伺服器威脅預報 ($(date +'%Y-%m-%d %H:%M')) ===" > "$FINAL_REPORT"
echo "資料範圍: $TODAY_STR" >> "$FINAL_REPORT"

# 分析 Top 50 惡意 IP (排除白名單)
awk '{print $1}' /tmp/today_working.log | grep -vE "$EXCLUDE_REGEX" | sort | uniq -c | sort -nr | head -n 50 > /tmp/top_ips.txt

while read count ip; do
    [[ -z $ip ]] && continue

    # --- [ 改進版 GeoIP 國家與機構判定 ] ---
    geo_raw=$(geoiplookup "$ip")
    # 排除 "GeoIP" 字眼防止抓到 "IP"，精準抓取兩位國家代碼
    country_code=$(echo "$geo_raw" | grep -v "ASNum" | sed 's/GeoIP//g' | grep -oE '[A-Z]{2}' | head -n 1)
    isp=$(echo "$geo_raw" | grep "ASNum" | awk -F': ' '{print $2}' | tr -d '\n')
    
    [[ -z "$country_code" ]] && country_code="??"

    # 威脅偵測 (SQLi / 掃描)
    sqli=$(grep "$ip" /tmp/today_working.log | grep -Ei "UNION|SELECT|XMLType|CHR\(" | wc -l)
    scanning=$(grep "$ip" /tmp/today_working.log | grep -Ei "\.env|\.git|wp-admin|config\.php" | wc -l)
    subnet=$(echo "$ip" | cut -d'.' -f1-3).0/24

    threats=""
    [[ $sqli -gt 0 ]] && threats+="[SQLi:$sqli] "
    [[ $scanning -gt 2 ]] && threats+="[掃描:$scanning] "
    [[ $count -gt 1500 ]] && threats+="[高頻:$count次] "

    # --- [ 分流邏輯 ] ---
    if [[ ! -z "$threats" ]]; then
        # 如果是台灣且沒有 SQLi，視為友善或誤判
        if [[ "$country_code" == "TW" && $sqli -eq 0 ]]; then
            echo -e "🔍 [BYPASS] IP: $ip | $country_code | $threats | $isp" >> "$FINAL_REPORT"
        else
            # 海外或國內 SQLi 一律標記封鎖
            echo -e "🚫 [\033[0;31mBLOCK\033[0m] IP: $ip | $country_code | $threats | $isp" >> "$FINAL_REPORT"
            echo "$subnet" >> "$SUSPECT_FILE"
        fi
    fi
done < /tmp/top_ips.txt

echo -e "\n分析完成！內容已寫入 $FINAL_REPORT"
cat "$FINAL_REPORT"
