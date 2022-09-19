
**宝塔7.7原版一键开心脚本**
```Bash
curl -sSO https://raw.githubusercontent.com/Jiaocha/bt77happy/main/bthappy/one_key_happy.sh && bash one_key_happy.sh
```

```Bash
手动解锁宝塔所有付费插件为永不过期

文件路径：www/server/panel/data/plugin.json
搜索字符串："endtime": -1 全部替换为 "endtime": 999999999999

手动阻止解锁插件后自动修复为免费版
chattr +i /www/server/panel/data/plugin.json
```
