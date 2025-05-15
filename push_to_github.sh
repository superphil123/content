#!/bin/bash

# 一鍵推送到 GitHub main 分支
# 用法：./push_to_github.sh <file_path> "<commit_message>"

if [ "$#" -ne 2 ]; then
    echo "❗ 使用方法: $0 <檔案路徑> "提交訊息""
    exit 1
fi

FILE=$1
MESSAGE=$2

if [ ! -f "$FILE" ]; then
    echo "❗ 檔案不存在: $FILE"
    exit 1
fi

echo "✅ 準備將 $FILE 推送到 GitHub main 分支..."
git add "$FILE"
git commit -m "$MESSAGE"
git push origin HEAD:master
echo "🎉 推送完成！"
