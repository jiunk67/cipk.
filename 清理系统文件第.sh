#!/bin/bash

# 1. 定义目标文件夹（请务必修改为实际文件所在路径，例如 /home/user/test）
target_dir="/storage/emulated/0/"

# 2. 检查目标文件夹是否存在
if [ ! -d "$target_dir" ]; then
    echo "错误：目标文件夹 \"$target_dir\" 不存在，请检查路径是否正确！"
    exit 1
fi

# 3. 进入目标文件夹
cd "$target_dir" || {
    echo "错误：无法进入目标文件夹 \"$target_dir\"！"
    exit 1
}

# 4. 查找并删除“系统文件第X”格式的文件（X为任意数字）
echo "正在查找 \"$target_dir\" 中符合“系统文件第X”格式的文件..."
deleted_count=0

# 匹配规则：文件名以“系统文件第”开头，以数字结尾（中间无其他字符）
for file in 系统文件第*; do
    # 用正则校验文件名是否符合“系统文件第+纯数字”格式
    if [[ "$file" =~ ^系统文件第[0-9]+$ ]]; then
        # 检查是否为文件（排除文件夹）
        if [ -f "$file" ]; then
            echo "正在删除：$file"
            rm -f "$file"  # -f 强制删除（无提示，忽略不存在的文件）
            if [ $? -eq 0 ]; then
                ((deleted_count++))
            else
                echo "警告：删除文件 \"$file\" 失败！"
            fi
        fi
    fi
done

# 5. 输出结果
if [ $deleted_count -eq 0 ]; then
    echo "未找到符合“系统文件第X”格式的文件，无需删除。"
else
    echo "操作完成！共成功删除 $deleted_count 个目标文件。"
fi
