备份全部文件
[lzhp529-main.zip](https://github.com/user-attachments/files/24733615/lzhp529-main.zip)


上面`github/workflows/update-subscriptions.yml`文件开头每小时运行一次原文：
```
name: Update Subscriptions - Simplified

on:
  schedule:
    # 每小时运行一次
    - cron: '0 * * * *'
  workflow_dispatch: # 允许手动触发
  push:
    paths:
      - '输入源/**'
      - 'scripts/**'
      - '.github/workflows/update-subscriptions.yml'
```
现在已经注释掉了，不再每小时运行，改为如下：
```
name: Update Subscriptions - Simplified

on:
  # schedule:
  #   # 每小时运行一次
  #   - cron: '0 * * * *'
  workflow_dispatch: # 允许手动触发
  push:
    paths:
      - '输入源/**'
      - 'scripts/**'
      - '.github/workflows/update-subscriptions.yml'

```
