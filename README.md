<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=32&pause=1000&color=FF6B9D&center=true&vCenter=true&width=600&lines=XJ+%E2%80%94+LT2+%E5%B7%A5%E5%85%B7%E5%BA%93;Lumber+Tycoon+2+Utils;%E4%B8%AD%E8%8B%B1%E5%8F%8C%E8%AF%AD+%C2%B7+%E6%8C%81%E7%BB%AD%E6%9B%B4%E6%96%B0" alt="Typing SVG" />

<br/>

![Lua](https://img.shields.io/badge/Lua-5.1%2B-2C2D72?style=for-the-badge&logo=lua&logoColor=white)
![Roblox](https://img.shields.io/badge/Roblox-LT2-E2231A?style=for-the-badge&logo=roblox&logoColor=white)
![License](https://img.shields.io/badge/License-Private-FF6B9D?style=for-the-badge)
![Files](https://img.shields.io/badge/Files-5-00D4AA?style=for-the-badge)

<br/>

> **XJ** 是为 Roblox《Lumber Tycoon 2》开发的数据工具库，  
> 收录树木翻译、商店翻译、多语言系统与 Asset ID 常量，  
> 供脚本开发者直接 `require` 或 `HttpGet` 引用。

</div>

---

## 📦 文件一览

| 文件 | 大小 | 用途 |
|------|------|------|
| [`TreeClass_中文翻译.lua`](./TreeClass_中文翻译.lua) | ~2 KB | TreeClass 英文 → 中文对照表，103 种树木 |
| [`asset_ids.lua`](./asset_ids.lua) | ~1 KB | 游戏内 Asset ID 常量（音效、图标等） |
| [`lang_data.lua`](./lang_data.lua) | ~37 KB | 完整多语言数据，152 个 key，中英双语 |
| [`翻译商店.lua`](./翻译商店.lua) | ~12 KB | 商店物品名称翻译工具 |

---

## 🚀 快速使用

### 远程加载（推荐）

```lua
-- TreeClass 中文翻译
local TREE_CN = loadstring(game:HttpGet(
  "https://raw.githubusercontent.com/jjyy1234/XJ/main/TreeClass_中文翻译.lua"
))()

-- 多语言数据
local LANG = loadstring(game:HttpGet(
  "https://raw.githubusercontent.com/jjyy1234/XJ/main/lang_data.lua"
))()

-- Asset ID 常量
local ASSETS = loadstring(game:HttpGet(
  "https://raw.githubusercontent.com/jjyy1234/XJ/main/asset_ids.lua"
))()
```

### 本地引用

```lua
local TREE_CN = require(script.Parent.TreeClass_中文翻译)
local LANG    = require(script.Parent.lang_data)
local ASSETS  = require(script.Parent.asset_ids)
```

---

## 🌲 TreeClass 翻译示例

```lua
print(TREE_CN["Generic"])      -- 普通树
print(TREE_CN["LoneCave"])     -- 幻影木
print(TREE_CN["SpookyGhoul"])  -- 幽灵食尸者
print(TREE_CN["Ethereal"])     -- 以太木
```

覆盖范围包括所有稀有树种：`BlueFlame` / `Ethereal` / `Infernal` / `Crystal` 等游戏后期新增树木。

---

## 🌐 多语言系统（lang_data）

`lang_data.lua` 返回一个包含 **152 个 key** 的双语对照表，支持中文 / 英文切换。

```lua
local LANG = { ... }

-- 取中文
local function t(key)
  return LANG[key] and LANG[key].zh or key
end

-- 取英文
local function te(key)
  return LANG[key] and LANG[key].en or key
end

print(t("auto_chop"))   -- 自动砍树
print(te("auto_chop"))  -- Auto Chop
```

---

## 🏪 商店翻译（翻译商店）

将游戏内商店物品的英文 InstanceName 映射到中文显示名，适用于蓝图购买、物品搜索等场景。

```lua
local SHOP = loadstring(game:HttpGet(
  "https://raw.githubusercontent.com/jjyy1234/XJ/main/翻译商店.lua"
))()

print(SHOP["WoodRamp"])   -- 木制斜坡
```

---

## 🔑 Asset IDs

```lua
local ASSETS = { ... }

-- 音效
game:GetService("SoundService"):PlayLocalSound(ASSETS.click_sfx)
-- ASSETS.click_sfx = 102257186883445（曼波音效）
```

---

## 📁 项目结构

```
XJ/
├── TreeClass_中文翻译.lua   # 树木翻译表
├── asset_ids.lua            # Asset ID 常量
├── lang_data.lua            # 多语言数据（152 key）
├── 翻译商店.lua              # 商店翻译
└── README.md
```

---

## ⚠️ 注意事项

- 本库专为 **Lumber Tycoon 2**（Roblox）设计，不适用于其他游戏
- 远程加载需要游戏开启 `HttpService`
- 文件名含中文，`HttpGet` 时 URL 需正确编码或直接使用 raw 链接
- 仅供个人脚本开发使用

---

<div align="center">

**由 [jjyy1234](https://github.com/jjyy1234) 维护 · YUTONGG 脚本体系**

![visitors](https://visitor-badge.laobi.icu/badge?page_id=jjyy1234.XJ)

</div>
