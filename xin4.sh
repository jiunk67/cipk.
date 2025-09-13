#!/bin/bash
echo ---Mt 管理器---
echo -----用扩展包运行-----
echo -----用扩展包运行-----
echo -----用扩展包运行-----
echo -----用扩展包运行-----
echo -----用扩展包运行-----
echo -----用扩展包运行-----
echo -----用扩展包运行-----
echo -----用扩展包运行-----
echo -----用扩展包运行-----
echo -----用扩展包运行-----
echo -----用扩展包运行-----


# 1. 显示系统信息
system_info() {
    echo -e "\n\033[1;34m===== 系统信息 =====\033[0m"
    echo "主机名: $(hostname)"
    echo "操作系统: $(uname -s)"
    echo "内核版本: $(uname -r)"
    echo "架构: $(uname -m)"
    echo "当前用户: $(whoami)"
    echo "系统运行时间: $(uptime -p)"
}

# 2. 显示CPU信息
cpu_info() {
    echo -e "\n\033[1;34m===== CPU信息 =====\033[0m"
    lscpu | grep -E 'Model name|Socket|Thread|Core|MHz'
}

# 3. 显示内存信息
mem_info() {
    echo -e "\n\033[1;34m===== 内存信息 =====\033[0m"
    free -h
}

# 4. 显示磁盘信息
disk_info() {
    echo -e "\n\033[1;34m===== 磁盘信息 =====\033[0m"
    df -h
}

# 5. 显示网络接口信息
network_info() {
    echo -e "\n\033[1;34m===== 网络信息 =====\033[0m"
    ip -br a
}

# 6. 显示进程按CPU使用率排序
top_processes() {
    echo -e "\n\033[1;34m===== 进程CPU使用率排行 =====\033[0m"
    ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 10
}

# 7. 显示进程按内存使用率排序
top_memory_processes() {
    echo -e "\n\033[1;34m===== 进程内存使用率排行 =====\033[0m"
    ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 10
}

# 8. 显示系统负载
system_load() {
    echo -e "\n\033[1;34m===== 系统负载 =====\033[0m"
    uptime
    echo "CPU核心数: $(nproc)"
}

# 9. 显示登录用户
logged_users() {
    echo -e "\n\033[1;34m===== 登录用户 =====\033[0m"
    who
}

# 10. 显示最近登录用户
last_logins() {
    echo -e "\n\033[1;34m===== 最近登录 =====\033[0m"
    last -n 5
}

# ==================== 文件操作类 ====================

# 11. 查找大文件
find_large_files() {
    echo -e "\n\033[1;34m===== 查找大文件(>100MB) =====\033[0m"
    find / -type f -size +100M -exec ls -lh {} + 2>/dev/null | awk '{ print $5 ": " $9 }'
}

# 12. 查找空文件和目录
find_empty() {
    echo -e "\n\033[1;34m===== 查找空文件和目录 =====\033[0m"
    find . -type f -empty
    find . -type d -empty
}

# 13. 计算文件行数
count_lines() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 文件行数统计 =====\033[0m"
        wc -l "$1"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 14. 计算文件单词数
count_words() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 文件单词统计 =====\033[0m"
        wc -w "$1"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 15. 计算文件字符数
count_chars() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 文件字符统计 =====\033[0m"
        wc -m "$1"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 16. 文件类型统计
file_types() {
    echo -e "\n\033[1;34m===== 文件类型统计 =====\033[0m"
    find . -type f | awk -F'.' '{print $NF}' | sort | uniq -c | sort -nr
}

# 17. 文件权限检查
check_permissions() {
    echo -e "\n\033[1;34m===== 文件权限检查 =====\033[0m"
    find . -type f -perm /o=w -exec ls -l {} +
}

# 18. 查找软链接
find_symlinks() {
    echo -e "\n\033[1;34m===== 查找软链接 =====\033[0m"
    find . -type l -exec ls -l {} +
}

# 19. 查找特定扩展名文件
find_by_ext() {
    if [ -z "$1" ]; then
        echo "请指定扩展名(如: txt)"
        return
    fi
    echo -e "\n\033[1;34m===== 查找.$1文件 =====\033[0m"
    find . -type f -name "*.$1"
}

# 20. 文件大小排序
sort_files_by_size() {
    echo -e "\n\033[1;34m===== 文件大小排序 =====\033[0m"
    find . -type f -exec ls -lh {} + | sort -k5 -rh | head -n 20
}

# ==================== 文本处理类 ====================

# 21. 统计文本中单词频率
word_frequency() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 单词频率统计 =====\033[0m"
        tr '[:space:]' '[\n*]' < "$1" | tr -d '[:punct:]' | tr '[:upper:]' '[:lower:]' | grep -v '^$' | sort | uniq -c | sort -nr
    else
        echo "文件不存在或未指定文件"
    fi
}

# 22. 查找重复行
find_duplicate_lines() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 查找重复行 =====\033[0m"
        sort "$1" | uniq -d
    else
        echo "文件不存在或未指定文件"
    fi
}

# 23. 删除重复行
remove_duplicate_lines() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 删除重复行 =====\033[0m"
        sort "$1" | uniq > "$1.tmp" && mv "$1.tmp" "$1"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 24. 行号显示
show_line_numbers() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 显示行号 =====\033[0m"
        cat -n "$1"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 25. 反转文件内容
reverse_file() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 反转文件内容 =====\033[0m"
        tac "$1"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 26. 随机打乱文件行
shuffle_lines() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 随机打乱文件行 =====\033[0m"
        shuf "$1"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 27. 提取特定行
extract_lines() {
    if [ -f "$1" ]; then
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "用法: extract_lines 文件名 起始行 结束行"
            return
        fi
        echo -e "\n\033[1;34m===== 提取行 $2-$3 =====\033[0m"
        sed -n "$2,$3p" "$1"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 28. 替换文本
replace_text() {
    if [ -f "$1" ]; then
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "用法: replace_text 文件名 旧文本 新文本"
            return
        fi
        echo -e "\n\033[1;34m===== 替换文本 =====\033[0m"
        sed -i "s/$2/$3/g" "$1"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 29. 删除空行
remove_empty_lines() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 删除空行 =====\033[0m"
        sed -i '/^$/d' "$1"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 30. 统计代码行数
count_code_lines() {
    echo -e "\n\033[1;34m===== 统计代码行数 =====\033[0m"
    find . -name "*.sh" -o -name "*.py" -o -name "*.js" -o -name "*.java" -o -name "*.c" -o -name "*.cpp" -o -name "*.h" | xargs wc -l
}

# ==================== 网络工具类 ====================

# 31. 检查端口是否开放
check_port() {
    if [ -z "$1" ]; then
        echo "用法: check_port 端口号"
        return
    fi
    echo -e "\n\033[1;34m===== 检查端口 $1 =====\033[0m"
    nc -zv 127.0.0.1 "$1" 2>&1 | grep succeeded
}

# 32. 获取公网IP
public_ip() {
    echo -e "\n\033[1;34m===== 公网IP =====\033[0m"
    curl ifconfig.me
    echo
}

# 33. 检查网站是否在线
check_website() {
    if [ -z "$1" ]; then
        echo "用法: check_website 网址"
        return
    fi
    echo -e "\n\033[1;34m===== 检查网站 $1 =====\033[0m"
    curl -I "$1" 2>/dev/null | head -n 1
}

# 34. 下载文件并显示进度
download_with_progress() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "用法: download_with_progress URL 保存路径"
        return
    fi
    echo -e "\n\033[1;34m===== 下载文件 =====\033[0m"
    wget --progress=bar:force "$1" -O "$2"
}

# 35. 测速
speed_test() {
    echo -e "\n\033[1;34m===== 网络测速 =====\033[0m"
    curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python -
}

# 36. 追踪路由
trace_route() {
    if [ -z "$1" ]; then
        echo "用法: trace_route 域名/IP"
        return
    fi
    echo -e "\n\033[1;34m===== 路由追踪 =====\033[0m"
    traceroute "$1"
}

# 37. 检查DNS解析
check_dns() {
    if [ -z "$1" ]; then
        echo "用法: check_dns 域名"
        return
    fi
    echo -e "\n\033[1;34m===== DNS解析检查 =====\033[0m"
    dig "$1" +short
}

# 38. 获取SSL证书信息
ssl_info() {
    if [ -z "$1" ]; then
        echo "用法: ssl_info 域名"
        return
    fi
    echo -e "\n\033[1;34m===== SSL证书信息 =====\033[0m"
    openssl s_client -connect "$1":443 -servername "$1" </dev/null 2>/dev/null | openssl x509 -noout -text | grep -E "Issuer:|Subject:|Not Before:|Not After :|DNS:"
}

# 39. 检查HTTP头
http_headers() {
    if [ -z "$1" ]; then
        echo "用法: http_headers 网址"
        return
    fi
    echo -e "\n\033[1;34m===== HTTP头信息 =====\033[0m"
    curl -I "$1"
}

# 40. 批量ping测试
batch_ping() {
    if [ -z "$1" ]; then
        echo "用法: batch_ping 文件(每行一个IP/域名)"
        return
    fi
    echo -e "\n\033[1;34m===== 批量ping测试 =====\033[0m"
    while read -r line; do
        ping -c 1 "$line" >/dev/null 2>&1 && echo "$line: 可达" || echo "$line: 不可达"
    done < "$1"
}

# ==================== 加密安全类 ====================

# 41. 生成随机密码
generate_password() {
    echo -e "\n\033[1;34m===== 生成随机密码 =====\033[0m"
    openssl rand -base64 12
}

# 42. 计算文件哈希
file_hash() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 文件哈希值 =====\033[0m"
        echo "MD5:    $(md5sum "$1" | awk '{print $1}')"
        echo "SHA1:   $(sha1sum "$1" | awk '{print $1}')"
        echo "SHA256: $(sha256sum "$1" | awk '{print $1}')"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 43. 加密文件
encrypt_file() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 加密文件 =====\033[0m"
        openssl aes-256-cbc -salt -in "$1" -out "$1.enc"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 44. 解密文件
decrypt_file() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 解密文件 =====\033[0m"
        openssl aes-256-cbc -d -salt -in "$1" -out "${1%.enc}"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 45. 检查SSH登录尝试
check_ssh_logins() {
    echo -e "\n\033[1;34m===== SSH登录尝试 =====\033[0m"
    grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr
}

# 46. 检查root登录
check_root_logins() {
    echo -e "\n\033[1;34m===== Root登录记录 =====\033[0m"
    last root
}

# 47. 检查sudo使用
check_sudo_usage() {
    echo -e "\n\033[1;34m===== Sudo使用记录 =====\033[0m"
    grep sudo /var/log/auth.log
}

# 48. 检查可疑进程
check_suspicious_processes() {
    echo -e "\n\033[1;34m===== 可疑进程检查 =====\033[0m"
    ps aux | grep -E "[n]map|[m]etasploit|[s]qlmap|[n]ikto|[h]ydra"
}

# 49. 检查异常连接
check_abnormal_connections() {
    echo -e "\n\033[1;34m===== 异常连接检查 =====\033[0m"
    netstat -tulnp | grep -E "127.0.0.1|0.0.0.0"
}

# 50. 检查crontab异常
check_crontab() {
    echo -e "\n\033[1;34m===== Crontab检查 =====\033[0m"
    crontab -l
    ls -la /etc/cron* /var/spool/cron/
}

# ==================== 开发工具类 ====================

# 51. 统计代码行数
count_code_lines() {
    echo -e "\n\033[1;34m===== 代码行数统计 =====\033[0m"
    find . -name "*.sh" -o -name "*.py" -o -name "*.js" -o -name "*.java" -o -name "*.c" -o -name "*.cpp" -o -name "*.h" | xargs wc -l
}

# 52. 格式化JSON
format_json() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 格式化JSON =====\033[0m"
        python -m json.tool "$1"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 53. 验证JSON
validate_json() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 验证JSON =====\033[0m"
        python -m json.tool "$1" >/dev/null && echo "有效的JSON" || echo "无效的JSON"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 54. 格式化XML
format_xml() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 格式化XML =====\033[0m"
        xmllint --format "$1"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 55. 验证XML
validate_xml() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 验证XML =====\033[0m"
        xmllint --noout "$1" && echo "有效的XML" || echo "无效的XML"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 56. 生成UUID
generate_uuid() {
    echo -e "\n\033[1;34m===== 生成UUID =====\033[0m"
    uuidgen
}

# 57. 生成随机数
random_number() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "用法: random_number 最小值 最大值"
        return
    fi
    echo -e "\n\033[1;34m===== 随机数生成 =====\033[0m"
    shuf -i "$1-$2" -n 1
}

# 58. 生成二维码
generate_qrcode() {
    if [ -z "$1" ]; then
        echo "用法: generate_qrcode 文本"
        return
    fi
    echo -e "\n\033[1;34m===== 生成二维码 =====\033[0m"
    echo "$1" | curl -F-=\<- qrenco.de
}

# 59. 解码二维码
decode_qrcode() {
    if [ -f "$1" ]; then
        echo -e "\n\033[1;34m===== 解码二维码 =====\033[0m"
        zbarimg "$1"
    else
        echo "文件不存在或未指定文件"
    fi
}

# 60. 计算表达式
calculate() {
    if [ -z "$1" ]; then
        echo "用法: calculate 表达式"
        return
    fi
    echo -e "\n\033[1;34m===== 计算结果 =====\033[0m"
    echo "$1" | bc -l
}

# ==================== 实用工具类 ====================

# 61. 天气查询
weather() {
    if [ -z "$1" ]; then
        echo "用法: weather 城市"
        return
    fi
    echo -e "\n\033[1;34m===== 天气查询 =====\033[0m"
    curl "wttr.in/$1?0"
}

# 62. 汇率查询
exchange_rate() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "用法: exchange_rate 货币1 货币2 (如: exchange_rate USD CNY)"
        return
    fi
    echo -e "\n\033[1;34m===== 汇率查询 =====\033[0m"
    curl "https://api.exchangerate-api.com/v4/latest/$1" | jq ".rates.$2"
}

# 63. 股票查询
stock_price() {
    if [ -z "$1" ]; then
        echo "用法: stock_price 股票代码"
        return
    fi
    echo -e "\n\033[1;34m===== 股票查询 =====\033[0m"
    curl -s "https://finance.yahoo.com/quote/$1" | grep -o 'regularMarketPrice[^}]*' | grep -o '"raw":[^,]*'
}

# 64. 翻译文本
translate() {
    if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
        echo "用法: translate 源语言 目标语言 文本"
        echo "示例: translate en zh 'Hello world'"
        return
    fi
    echo -e "\n\033[1;34m===== 翻译结果 =====\033[0m"
    curl -s "https://translate.googleapis.com/translate_a/single?client=gtx&sl=$1&tl=$2&dt=t&q=$(echo "$3" | sed 's/ /%20/g')" | jq -r '.[0][0][0]'
}

# 65. 生成ASCII艺术字
ascii_art() {
    if [ -z "$1" ]; then
        echo "用法: ascii_art 文本"
        return
    fi
    echo -e "\n\033[1;34m===== ASCII艺术字 =====\033[0m"
    figlet "$1"
}

# 66. 生成条形码
generate_barcode() {
    if [ -z "$1" ]; then
        echo "用法: generate_barcode 文本"
        return
    fi
    echo -e "\n\033[1;34m===== 生成条形码 =====\033[0m"
    echo "$1" | curl -F-=\<- barcode.tec-it.com/barcode.ashx
}

# 67. 计算日期差
date_diff() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "用法: date_diff 日期1 日期2 (格式: YYYY-MM-DD)"
        return
    fi
    echo -e "\n\033[1;34m===== 日期差计算 =====\033[0m"
    echo $(( ($(date -d "$1" +%s) - $(date -d "$2" +%s)) / 86400 )) "天"
}

# 68. 计算工作日
working_days() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "用法: working_days 开始日期 结束日期 (格式: YYYY-MM-DD)"
        return
    fi
    echo -e "\n\033[1;34m===== 工作日计算 =====\033[0m"
    start=$(date -d "$1" +%s)
    end=$(date -d "$2" +%s)
    days=$(( (end - start) / 86400 + 1 ))
    weeks=$(( days / 7 ))
    extra_days=$(( days % 7 ))
    
    if [ $extra_days -gt 0 ]; then
        start_day=$(date -d "$1" +%u)
        end_day=$(( start_day + extra_days - 1 ))
        if [ $end_day -gt 7 ]; then
            end_day=$(( end_day - 7 ))
        fi
        if [ $start_day -le $end_day ]; then
            weekend_days=$(( (end_day >= 6 ? 2 : 0) - (start_day >= 6 ? 2 : 0) ))
        else
            weekend_days=$(( (end_day >= 6 ? 2 : 0) + (start_day <= 6 ? 0 : 2) ))
        fi
    else
        weekend_days=0
    fi
    
    total_weekend_days=$(( weeks * 2 + weekend_days ))
    working_days=$(( days - total_weekend_days ))
    echo "$working_days 个工作日"
}

# 69. 倒计时
countdown() {
    if [ -z "$1" ]; then
        echo "用法: countdown 秒数"
        return
    fi
    echo -e "\n\033[1;34m===== 倒计时开始 =====\033[0m"
    for ((i=$1; i>=0; i--)); do
        printf "\r%02d:%02d" $((i/60)) $((i%60))
        sleep 1
    done
    echo -e "\n时间到！"
}

# 70. 计时器
stopwatch() {
    echo -e "\n\033[1;34m===== 计时器开始 =====\033[0m"
    echo "按Ctrl+C停止"
    start=$(date +%s)
    while true; do
        now=$(date +%s)
        diff=$((now - start))
        printf "\r%02d:%02d:%02d" $((diff/3600)) $(((diff/60)%60)) $((diff%60))
        sleep 1
    done
}

# ==================== 游戏娱乐类 ====================

# 71. 猜数字游戏
guess_number() {
    echo -e "\n\033[1;34m===== 猜数字游戏 =====\033[0m"
    number=$((RANDOM % 100 + 1))
    attempts=0
    
    while true; do
        read -p "猜一个1-100的数字: " guess
        if ! [[ "$guess" =~ ^[0-9]+$ ]]; then
            echo "请输入数字！"
            continue
        fi
        ((attempts++))
        
        if [ "$guess" -lt "$number" ]; then
            echo "太小了！"
        elif [ "$guess" -gt "$number" ]; then
            echo "太大了！"
        else
            echo "恭喜！你猜对了，用了 $attempts 次尝试。"
            break
        fi
    done
}

# 72. 石头剪刀布
rock_paper_scissors() {
    echo -e "\n\033[1;34m===== 石头剪刀布 =====\033[0m"
    options=("石头" "剪刀" "布")
    computer=$((RANDOM % 3))
    
    echo "选择:"
    echo "1. 石头"
    echo "2. 剪刀"
    echo "3. 布"
    read -p "输入你的选择(1-3): " player
    ((player--))
    
    if [ "$player" -lt 0 ] || [ "$player" -gt 2 ]; then
        echo "无效选择！"
        return
    fi
    
    echo "你选择了: ${options[$player]}"
    echo "电脑选择了: ${options[$computer]}"
    
    if [ "$player" -eq "$computer" ]; then
        echo "平局！"
    elif [ "$(( (player - computer + 3) % 3 ))" -eq 1 ]; then
        echo "你输了！"
    else
        echo "你赢了！"
    fi
}

# 73. 记忆游戏
memory_game() {
    echo -e "\n\033[1;34m===== 记忆游戏 =====\033[0m"
    sequence=()
    for i in {1..5}; do
        sequence+=($((RANDOM % 10)))
    done
    
    echo "记住这个序列: ${sequence[*]}"
    sleep 5
    clear
    
    echo "输入你记住的序列(用空格分隔):"
    read -a user_sequence
    
    if [ "${sequence[*]}" = "${user_sequence[*]}" ]; then
        echo "恭喜！你记住了！"
    else
        echo "错误！正确序列是: ${sequence[*]}"
    fi
}

# 74. 井字棋
tic_tac_toe() {
    echo -e "\n\033[1;34m===== 井字棋 =====\033[0m"
    board=(" " " " " " " " " " " " " " " " " ")
    current_player="X"
    
    print_board() {
        echo " ${board[0]} | ${board[1]} | ${board[2]} "
        echo "-----------"
        echo " ${board[3]} | ${board[4]} | ${board[5]} "
        echo "-----------"
        echo " ${board[6]} | ${board[7]} | ${board[8]} "
    }
    
    check_winner() {
        # 检查行
        for i in 0 3 6; do
            if [ "${board[$i]}" != " " ] && [ "${board[$i]}" = "${board[$((i+1))]}" ] && [ "${board[$i]}" = "${board[$((i+2))]}" ]; then
                return 0
            fi
        done
        
        # 检查列
        for i in 0 1 2; do
            if [ "${board[$i]}" != " " ] && [ "${board[$i]}" = "${board[$((i+3))]}" ] && [ "${board[$i]}" = "${board[$((i+6))]}" ]; then
                return 0
            fi
        done
        
        # 检查对角线
        if [ "${board[0]}" != " " ] && [ "${board[0]}" = "${board[4]}" ] && [ "${board[0]}" = "${board[8]}" ]; then
            return 0
        fi
        
        if [ "${board[2]}" != " " ] && [ "${board[2]}" = "${board[4]}" ] && [ "${board[2]}" = "${board[6]}" ]; then
            return 0
        fi
        
        return 1
    }
    
    while true; do
        print_board
        echo "玩家 $current_player 的回合"
        read -p "输入位置(1-9): " position
        
        if ! [[ "$position" =~ ^[1-9]$ ]]; then
            echo "无效输入！请输入1-9的数字。"
            continue
        fi
        
        ((position--))
        
        if [ "${board[$position]}" != " " ]; then
            echo "该位置已被占用！"
            continue
        fi
        
        board[$position]=$current_player
        
        if check_winner; then
            print_board
            echo "玩家 $current_player 获胜！"
            break
        fi
        
        if ! [[ " ${board[*]} " =~ " " ]]; then
            print_board
            echo "平局！"
            break
        fi
        
        if [ "$current_player" = "X" ]; then
            current_player="O"
        else
            current_player="X"
        fi
    done
}

# 75. 21点游戏
blackjack() {
    echo -e "\n\033[1;34m===== 21点游戏 =====\033[0m"
    deck=()
    for i in {1..4}; do
        deck+=(A 2 3 4 5 6 7 8 9 10 J Q K)
    done
    
    shuffle_deck() {
        local i tmp size
        size=${#deck[@]}
        for ((i=size-1; i>0; i--)); do
            j=$((RANDOM % (i+1)))
            tmp=${deck[i]}
            deck[i]=${deck[j]}
            deck[j]=$tmp
        done
    }
    
    card_value() {
        case $1 in
            A) echo 11 ;;
            J|Q|K) echo 10 ;;
            *) echo $1 ;;
        esac
    }
    
    hand_value() {
        local sum=0
        local aces=0
        for card in "$@"; do
            val=$(card_value "$card")
            sum=$((sum + val))
            if [ "$card" = "A" ]; then
                aces=$((aces + 1))
            fi
        done
        
        while [ "$sum" -gt 21 ] && [ "$aces" -gt 0 ]; do
            sum=$((sum - 10))
            aces=$((aces - 1))
        done
        
        echo $sum
    }
    
    shuffle_deck
    player_hand=("${deck[0]}" "${deck[1]}")
    dealer_hand=("${deck[2]}" "${deck[3]}")
    deck=("${deck[@]:4}")
    
    player_total=$(hand_value "${player_hand[@]}")
    dealer_total=$(hand_value "${dealer_hand[@]}")
    
    echo "你的手牌: ${player_hand[*]} (总计: $player_total)"
    echo "庄家的明牌: ${dealer_hand[0]}"
    
    # 玩家回合
    while [ "$player_total" -lt 21 ]; do
        read -p "要牌(h)或停牌(s)? " choice
        case $choice in
            h)
                player_hand+=("${deck[0]}")
                deck=("${deck[@]:1}")
                player_total=$(hand_value "${player_hand[@]}")
                echo "你的手牌: ${player_hand[*]} (总计: $player_total)"
                
                if [ "$player_total" -gt 21 ]; then
                    echo "爆牌！你输了。"
                    return
                fi
                ;;
            s)
                break
                ;;
            *)
                echo "无效选择！"
                ;;
        esac
    done
    
    # 庄家回合
    echo "庄家的手牌: ${dealer_hand[*]} (总计: $dealer_total)"
    while [ "$dealer_total" -lt 17 ]; do
        dealer_hand+=("${deck[0]}")
        deck=("${deck[@]:1}")
        dealer_total=$(hand_value "${dealer_hand[@]}")
        echo "庄家要牌: ${dealer_hand[-1]}"
        echo "庄家的手牌: ${dealer_hand[*]} (总计: $dealer_total)"
        
        if [ "$dealer_total" -gt 21 ]; then
            echo "庄家爆牌！你赢了。"
            return
        fi
    done
    
    # 比较分数
    if [ "$player_total" -gt "$dealer_total" ]; then
        echo "你赢了！ ($player_total vs $dealer_total)"
    elif [ "$player_total" -lt "$dealer_total" ]; then
        echo "你输了。 ($player_total vs $dealer_total)"
    else
        echo "平局！ ($player_total vs $dealer_total)"
    fi
}

# ==================== 系统管理类 ====================

# 76. 清理临时文件
clean_tmp() {
    echo -e "\n\033[1;34m===== 清理临时文件 =====\033[0m"
    sudo find /tmp -type f -atime +7 -delete
    sudo find /var/tmp -type f -atime +7 -delete
    echo "临时文件清理完成"
}

# 77. 清理日志文件
clean_logs() {
    echo -e "\n\033[1;34m===== 清理日志文件 =====\033[0m"
    sudo find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
    echo "日志文件已清空"
}

# 78. 清理缓存
clean_cache() {
    echo -e "\n\033[1;34m===== 清理缓存 =====\033[0m"
    sudo sync && echo 3 | sudo tee /proc/sys/vm/drop_caches
    echo "缓存已清理"
}

# 79. 清理旧内核
clean_old_kernels() {
    echo -e "\n\033[1;34m===== 清理旧内核 =====\033[0m"
    sudo apt-get autoremove --purge
    echo "旧内核已清理"
}

# 80. 清理Docker
clean_docker() {
    echo -e "\n\033[1;34m===== 清理Docker =====\033[0m"
    docker system prune -af
    echo "Docker已清理"
}

# ==================== 高级功能类 ====================

# 81. 监控目录变化
monitor_directory() {
    if [ -z "$1" ]; then
        echo "用法: monitor_directory 目录路径"
        return
    fi
    echo -e "\n\033[1;34m===== 监控目录变化 =====\033[0m"
    inotifywait -m -r -e create,delete,modify,move "$1"
}

# 82. 批量重命名文件
batch_rename() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "用法: batch_rename 模式 替换 (如: batch_rename '*.txt' '.bak')"
        return
    fi
    echo -e "\n\033[1;34m===== 批量重命名文件 =====\033[0m"
    for file in $1; do
        mv "$file" "${file%.*}$2"
    done
}

# 83. 批量转换图片格式
convert_images() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "用法: convert_images 源格式 目标格式 (如: convert_images jpg png)"
        return
    fi
    echo -e "\n\033[1;34m===== 批量转换图片格式 =====\033[0m"
    for file in *."$1"; do
        convert "$file" "${file%.*}.$2"
    done
}

# 84. 批量调整图片大小
resize_images() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "用法: resize_images 宽度 高度 (如: resize_images 800 600)"
        return
    fi
    echo -e "\n\033[1;34m===== 批量调整图片大小 =====\033[0m"
    for file in *.{jpg,jpeg,png,gif}; do
        convert "$file" -resize "$1x$2" "resized_$file"
    done
}

# 85. 批量添加水印
add_watermark() {
    if [ -z "$1" ]; then
        echo "用法: add_watermark 水印文本"
        return
    fi
    echo -e "\n\033[1;34m===== 批量添加水印 =====\033[0m"
    for file in *.{jpg,jpeg,png,gif}; do
        convert "$file" -gravity southeast -pointsize 36 -fill white -annotate +10+10 "$1" "watermarked_$file"
    done
}

# 86. 批量压缩图片
compress_images() {
    if [ -z "$1" ]; then
        echo "用法: compress_images 质量(1-100)"
        return
    fi
    echo -e "\n\033[1;34m===== 批量压缩图片 =====\033[0m"
    for file in *.{jpg,jpeg,png,gif}; do
        convert "$file" -quality "$1" "compressed_$file"
    done
}

# 87. 批量转换视频格式
convert_videos() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "用法: convert_videos 源格式 目标格式 (如: convert_videos avi mp4)"
        return
    fi
    echo -e "\n\033[1;34m===== 批量转换视频格式 =====\033[0m"
    for file in *."$1"; do
        ffmpeg -i "$file" "${file%.*}.$2"
    done
}

# 88. 批量提取音频
extract_audio() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "用法: extract_audio 视频格式 音频格式 (如: extract_audio mp4 mp3)"
        return
    fi
    echo -e "\n\033[1;34m===== 批量提取音频 =====\033[0m"
    for file in *."$1"; do
        ffmpeg -i "$file" -vn -acodec copy "${file%.*}.$2"
    done
}

# 89. 批量截图视频
video_screenshots() {
    if [ -z "$1" ]; then
        echo "用法: video_screenshots 视频格式"
        return
    fi
    echo -e "\n\033[1;34m===== 批量截图视频 =====\033[0m"
    for file in *."$1"; do
        ffmpeg -i "$file" -ss 00:00:05 -vframes 1 "${file%.*}.jpg"
    done
}

# 90. 批量合并PDF
merge_pdfs() {
    if [ -z "$1" ]; then
        echo "用法: merge_pdfs 输出文件名 (如: merge_pdfs combined.pdf)"
        return
    fi
    echo -e "\n\033[1;34m===== 批量合并PDF =====\033[0m"
    gs -dBATCH -dNOPAUSE -q -sDEVICE=pdfwrite -sOutputFile="$1" *.pdf
}

# ==================== 其他有趣功能 ====================

# 91. 生成随机密码短语
generate_passphrase() {
    echo -e "\n\033[1;34m===== 生成随机密码短语 =====\033[0m"
    words=("apple" "banana" "cherry" "date" "elderberry" "fig" "grape" "honeydew" "kiwi" "lemon")
    passphrase=""
    for i in {1..4}; do
        word=${words[$((RANDOM % ${#words[@]}))]}
        passphrase="$passphrase$word"
    done
    echo "$passphrase"
}

# 92. 生成随机名字
random_name() {
    echo -e "\n\033[1;34m===== 生成随机名字 =====\033[0m"
    first_names=("Alice" "Bob" "Charlie" "David" "Eve" "Frank" "Grace" "Heidi" "Ivan" "Judy")
    last_names=("Smith" "Johnson" "Williams" "Brown" "Jones" "Miller" "Davis" "Garcia" "Rodriguez" "Wilson")
    echo "${first_names[$((RANDOM % ${#first_names[@]}))]} ${last_names[$((RANDOM % ${#last_names[@]}))]}"
}

# 93. 生成随机地址
random_address() {
    echo -e "\n\033[1;34m===== 生成随机地址 =====\033[0m"
    streets=("Main" "Oak" "Pine" "Maple" "Cedar" "Elm" "View" "Washington" "Lake" "Hill")
    cities=("New York" "Los Angeles" "Chicago" "Houston" "Phoenix" "Philadelphia" "San Antonio" "San Diego" "Dallas" "San Jose")
    echo "$((RANDOM % 9999)) ${streets[$((RANDOM % ${#streets[@]}))]} St, ${cities[$((RANDOM % ${#cities[@]}))]}, $((RANDOM % 50 + 1))$(printf \\$(printf '%03o' $((RANDOM % 26 + 65)))) $((RANDOM % 99999 + 10000))"
}

# 94. 生成随机颜色
random_color() {
    echo -e "\n\033[1;34m===== 生成随机颜色 =====\033[0m"
    printf "#%06x\n" $((RANDOM % 0x1000000))
}

# 95. 生成随机日期
random_date() {
    echo -e "\n\033[1;34m===== 生成随机日期 =====\033[0m"
    year=$((RANDOM % 50 + 1970))
    month=$((RANDOM % 12 + 1))
    day=$((RANDOM % 28 + 1))
    printf "%04d-%02d-%02d\n" $year $month $day
}

# 96. 生成随机时间
random_time() {
    echo -e "\n\033[1;34m===== 生成随机时间 =====\033[0m"
    hour=$((RANDOM % 24))
    minute=$((RANDOM % 60))
    second=$((RANDOM % 60))
    printf "%02d:%02d:%02d\n" $hour $minute $second
}

# 97. 生成随机IP地址
random_ip() {
    echo -e "\n\033[1;34m===== 生成随机IP地址 =====\033[0m"
    printf "%d.%d.%d.%d\n" $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256))
}

# 98. 生成随机MAC地址
random_mac() {
    echo -e "\n\033[1;34m===== 生成随机MAC地址 =====\033[0m"
    printf "%02x:%02x:%02x:%02x:%02x:%02x\n" $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256))
}

# 99. 生成随机信用卡号
random_credit_card() {
    echo -e "\n\033[1;34m===== 生成随机信用卡号 =====\033[0m"
    printf "%04d %04d %04d %04d\n" $((RANDOM % 10000)) $((RANDOM % 10000)) $((RANDOM % 10000)) $((RANDOM % 10000))
}

# 100. 生成随机UUID
random_uuid() {
    echo -e "\n\033[1;34m===== 生成随机UUID =====\033[0m"
    uuidgen
}

# 显示菜单
show_menu() {
    echo -e "\n\033[1;35m===== 100个高级Shell脚本功能 =====\033[0m"
    echo "1. 系统信息"
    echo "2. CPU信息"
    echo "3. 内存信息"
    echo "4. 磁盘信息"
    echo "5. 网络信息"
    echo "6. 进程CPU使用率排行"
    echo "7. 进程内存使用率排行"
    echo "8. 系统负载"
    echo "9. 登录用户"
    echo "10. 最近登录"
    echo "11. 查找大文件"
    echo "12. 查找空文件和目录"
    echo "13. 计算文件行数"
    echo "14. 计算文件单词数"
    echo "15. 计算文件字符数"
    echo "16. 文件类型统计"
    echo "17. 文件权限检查"
    echo "18. 查找软链接"
    echo "19. 查找特定扩展名文件"
    echo "20. 文件大小排序"
    echo "21. 统计文本中单词频率"
    echo "22. 查找重复行"
    echo "23. 删除重复行"
    echo "24. 行号显示"
    echo "25. 反转文件内容"
    echo "26. 随机打乱文件行"
    echo "27. 提取特定行"
    echo "28. 替换文本"
    echo "29. 删除空行"
    echo "30. 统计代码行数"
    echo "31. 检查端口是否开放"
    echo "32. 获取公网IP"
    echo "33. 检查网站是否在线"
    echo "34. 下载文件并显示进度"
    echo "35. 测速"
    echo "36. 追踪路由"
    echo "37. 检查DNS解析"
    echo "38. 获取SSL证书信息"
    echo "39. 检查HTTP头"
    echo "40. 批量ping测试"
    echo "41. 生成随机密码"
    echo "42. 计算文件哈希"
    echo "43. 加密文件"
    echo "44. 解密文件"
    echo "45. 检查SSH登录尝试"
    echo "46. 检查root登录"
    echo "47. 检查sudo使用"
    echo "48. 检查可疑进程"
    echo "49. 检查异常连接"
    echo "50. 检查crontab异常"
    echo "51. 统计代码行数"
    echo "52. 格式化JSON"
    echo "53. 验证JSON"
    echo "54. 格式化XML"
    echo "55. 验证XML"
    echo "56. 生成UUID"
    echo "57. 生成随机数"
    echo "58. 生成二维码"
    echo "59. 解码二维码"
    echo "60. 计算表达式"
    echo "61. 天气查询"
    echo "62. 汇率查询"
    echo "63. 股票查询"
    echo "64. 翻译文本"
    echo "65. 生成ASCII艺术字"
    echo "66. 生成条形码"
    echo "67. 计算日期差"
    echo "68. 计算工作日"
    echo "69. 倒计时"
    echo "70. 计时器"
    echo "71. 猜数字游戏"
    echo "72. 石头剪刀布"
    echo "73. 记忆游戏"
    echo "74. 井字棋"
    echo "75. 21点游戏"
    echo "76. 清理临时文件"
    echo "77. 清理日志文件"
    echo "78. 清理缓存"
    echo "79. 清理旧内核"
    echo "80. 清理Docker"
    echo "81. 监控目录变化"
    echo "82. 批量重命名文件"
    echo "83. 批量转换图片格式"
    echo "84. 批量调整图片大小"
    echo "85. 批量添加水印"
    echo "86. 批量压缩图片"
    echo "87. 批量转换视频格式"
    echo "88. 批量提取音频"
    echo "89. 批量截图视频"
    echo "90. 批量合并PDF"
    echo "91. 生成随机密码短语"
    echo "92. 生成随机名字"
    echo "93. 生成随机地址"
    echo "94. 生成随机颜色"
    echo "95. 生成随机日期"
    echo "96. 生成随机时间"
    echo "97. 生成随机IP地址"
    echo "98. 生成随机MAC地址"
    echo "99. 生成随机信用卡号"
    echo "100. 生成随机UUID"
    echo -e "\033[1;35m================================\033[0m"
    echo "0. 退出"
}

# 主循环
while true; do
    show_menu
    read -p "请输入功能编号(1-100): " choice
    
    case $choice in
        1) system_info ;;
        2) cpu_info ;;
        3) mem_info ;;
        4) disk_info ;;
        5) network_info ;;
        6) top_processes ;;
        7) top_memory_processes ;;
        8) system_load ;;
        9) logged_users ;;
        10) last_logins ;;
        11) find_large_files ;;
        12) find_empty ;;
        13) count_lines "$@" ;;
        14) count_words "$@" ;;
        15) count_chars "$@" ;;
        16) file_types ;;
        17) check_permissions ;;
        18) find_symlinks ;;
        19) find_by_ext "$@" ;;
        20) sort_files_by_size ;;
        21) word_frequency "$@" ;;
        22) find_duplicate_lines "$@" ;;
        23) remove_duplicate_lines "$@" ;;
        24) show_line_numbers "$@" ;;
        25) reverse_file "$@" ;;
        26) shuffle_lines "$@" ;;
        27) extract_lines "$@" ;;
        28) replace_text "$@" ;;
        29) remove_empty_lines "$@" ;;
        30) count_code_lines ;;
        31) check_port "$@" ;;
        32) public_ip ;;
        33) check_website "$@" ;;
        34) download_with_progress "$@" ;;
        35) speed_test ;;
        36) trace_route "$@" ;;
        37) check_dns "$@" ;;
        38) ssl_info "$@" ;;
        39) http_headers "$@" ;;
        40) batch_ping "$@" ;;
        41) generate_password ;;
        42) file_hash "$@" ;;
        43) encrypt_file "$@" ;;
        44) decrypt_file "$@" ;;
        45) check_ssh_logins ;;
        46) check_root_logins ;;
        47) check_sudo_usage ;;
        48) check_suspicious_processes ;;
        49) check_abnormal_connections ;;
        50) check_crontab ;;
        51) count_code_lines ;;
        52) format_json "$@" ;;
        53) validate_json "$@" ;;
        54) format_xml "$@" ;;
        55) validate_xml "$@" ;;
        56) generate_uuid ;;
        57) random_number "$@" ;;
        58) generate_qrcode "$@" ;;
        59) decode_qrcode "$@" ;;
        60) calculate "$@" ;;
        61) weather "$@" ;;
        62) exchange_rate "$@" ;;
        63) stock_price "$@" ;;
        64) translate "$@" ;;
        65) ascii_art "$@" ;;
        66) generate_barcode "$@" ;;
        67) date_diff "$@" ;;
        68) working_days "$@" ;;
        69) countdown "$@" ;;
        70) stopwatch ;;
        71) guess_number ;;
        72) rock_paper_scissors ;;
        73) memory_game ;;
        74) tic_tac_toe ;;
        75) blackjack ;;
        76) clean_tmp ;;
        77) clean_logs ;;
        78) clean_cache ;;
        79) clean_old_kernels ;;
        80) clean_docker ;;
        81) monitor_directory "$@" ;;
        82) batch_rename "$@" ;;
        83) convert_images "$@" ;;
        84) resize_images "$@" ;;
        85) add_watermark "$@" ;;
        86) compress_images "$@" ;;
        87) convert_videos "$@" ;;
        88) extract_audio "$@" ;;
        89) video_screenshots "$@" ;;
        90) merge_pdfs "$@" ;;
        91) generate_passphrase ;;
        92) random_name ;;
        93) random_address ;;
        94) random_color ;;
        95) random_date ;;
        96) random_time ;;
        97) random_ip ;;
        98) random_mac ;;
        99) random_credit_card ;;
        100) random_uuid ;;
        0) echo "再见！"; exit 0 ;;
        *) echo "无效选择！" ;;
    esac
    
    read -p "按回车键继续..."
done
