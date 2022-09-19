 宝塔面板7.7原版安装
```Bash
curl -sSO https://raw.githubusercontent.com/Jiaocha/bt77happy/main/install/install_panel.sh && bash install_panel.sh
```

 宝塔7.7原版一键开心脚本
```Bash
curl -sSO https://raw.githubusercontent.com/Jiaocha/bt77happy/main/bthappy/one_key_happy.sh && bash one_key_happy.sh
```

 降级
```Bash
wget https://raw.githubusercontent.com/Jiaocha/bt77happy/main/install/src/LinuxPanel-7.7.0.zip
unzip LinuxPanel-*
cd panel
bash update.sh
cd .. && rm -f LinuxPanel-*.zip && rm -rf panel
```

 删除手机验证
```Bash
rm -f /www/server/panel/data/bind.pl
```

 手动解锁宝塔所有付费插件为永不过期
```Bash
文件路径：www/server/panel/data/plugin.json
搜索字符串："endtime": -1 全部替换为 "endtime": 999999999999
```
 手动阻止解锁插件后自动修复为免费版
```Bash
chattr +i /www/server/panel/data/plugin.json
```

 宝塔linux工具箱优化脚本
一键修改宝塔面板模板、去除强制登陆、一键修复面板、一键更换yum源、清除系统垃圾缓存、系统优化等
```Bash
wget -O btpanel_tools.sh https://cdn.jsdelivr.net/gh/Jiaocha/bt77happy@main/btpanel_tools/btpanel_tools.sh && bash btpanel_tools.sh
```
