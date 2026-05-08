# BLE Relay over MQTT

[English](README.md) | **中文**

基于 MQTT 的 BLE（低功耗蓝牙）链路层中继攻击工具，实现跨网络远距离中继。基于 [Sniffle](https://github.com/nccgroup/Sniffle) BLE 嗅探框架开发。

## 概述

传统 BLE 中继攻击要求两个中继节点在同一局域网内（TCP 直连）。本工具使用 MQTT Broker 作为传输层，突破该限制，实现跨互联网中继攻击 —— 不受地理位置限制。

```
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│   手机/Central   │◄──BLE──►│  relay_peripheral │         │                  │
│  (如：App)       │         │  (手机侧)         │         │   MQTT Broker    │
└──────────────────┘         │  + Sniffle 板子   │◄──MQTT──►  (公网服务器)     │
                             └──────────────────┘         │                  │
                                                          └────────┬─────────┘
                                                                   │ MQTT
                             ┌──────────────────┐                  │
                             │   relay_central   │◄─────────────────┘
                             │  (设备侧)         │
                             │  + Sniffle 板子   │◄──BLE──►┌──────────────────┐
                             └──────────────────┘         │  BLE 外设        │
                                                          │  (如：车辆 PKE)   │
                                                          └──────────────────┘
```

## 工作原理

1. **设备侧** (`relay_central.py`) 扫描并捕获目标外设的 ADV_IND + SCAN_RSP
2. 捕获的广播数据通过 MQTT broker 发布（带 retain 标志）
3. **手机侧** (`relay_peripheral.py`) 订阅 MQTT，接收广播数据，克隆目标的 BLE 身份
4. 手机侧开始广播，等待合法中心设备（手机）连接
5. 手机连接后，CONNECT_IND 通过 MQTT 转发到设备侧
6. 设备侧使用 CONNECT_IND 参数与真实外设建立 BLE 连接
7. 后续所有链路层数据 PDU 通过 MQTT 双向中继

## 前置要求

### 硬件

- **2 块 TI CC1352/CC2652 开发板**（如 LAUNCHXL-CC1352R1 或 LAUNCHXL-CC26X2R1），刷入 [Sniffle 固件](https://github.com/nccgroup/Sniffle)
- USB 线连接开发板到电脑

### 软件

- Python 3.8+
- 两个中继节点均可访问的 MQTT broker（如 [Mosquitto](https://mosquitto.org/)、[EMQX](https://www.emqx.io/)）

### MQTT Broker 搭建

需要一个公网可达的 MQTT broker。选项：

1. **自建 Mosquitto**（推荐）：
   ```bash
   # 在你的 VPS/云服务器上
   sudo apt install mosquitto mosquitto-clients
   sudo systemctl enable --now mosquitto
   ```

2. **云 MQTT 服务**：EMQX Cloud、HiveMQ Cloud 等

> ⚠️ 仅用于安全研究。生产环境的 MQTT broker 请确保配置认证。

## 安装

```bash
git clone https://github.com/yourname/RelayonMQTT.git
cd RelayonMQTT
pip install -r requirements.txt
```

## 使用方法

### 步骤一：启动设备侧中继（靠近目标外设）

```bash
python relay_central.py -B <MQTT_BROKER_IP> -t <目标MAC> -s <串口>
```

示例：
```bash
python relay_central.py -B mqtt.example.com -t C6:07:59:15:53:5F -s /dev/ttyACM0
```

### 步骤二：启动手机侧中继（靠近手机/中心设备）

```bash
python relay_peripheral.py -B <MQTT_BROKER_IP> -s <串口>
```

示例：
```bash
python relay_peripheral.py -B mqtt.example.com -s /dev/ttyACM1
```

> **注意：** 由于使用了 MQTT retained 消息，启动顺序无关紧要。设备侧中继以 retain 标志发布广播数据，手机侧中继即使晚启动也能收到。

### 命令行参数

#### `relay_central.py`（设备侧）

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-B`, `--broker` | MQTT broker 地址（必填） | — |
| `-P`, `--mqtt-port` | MQTT broker 端口 | 1883 |
| `-t`, `--target` | 目标 BLE MAC 地址（必填） | — |
| `-s`, `--serport` | Sniffle 串口 | 自动检测 |
| `-o`, `--output` | PCAP 输出文件 | 无 |
| `-q`, `--quiet` | 静默模式，不打印每包信息 | false |
| `--pub-topic` | MQTT 发布主题 | `/ble_relay/to_phone` |
| `--sub-topic` | MQTT 订阅主题 | `/ble_relay/to_device` |

#### `relay_peripheral.py`（手机侧）

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-B`, `--broker` | MQTT broker 地址（必填） | — |
| `-P`, `--mqtt-port` | MQTT broker 端口 | 1883 |
| `-s`, `--serport` | Sniffle 串口 | 自动检测 |
| `-o`, `--output` | PCAP 输出文件 | 无 |
| `-q`, `--quiet` | 静默模式，不打印每包信息 | false |
| `--pub-topic` | MQTT 发布主题 | `/ble_relay/to_device` |
| `--sub-topic` | MQTT 订阅主题 | `/ble_relay/to_phone` |

## 协议格式

中继节点间通过 MQTT 交换的消息使用简单文本协议：

| 前缀 | 方向 | 说明 |
|------|------|------|
| `adv:<hex>` | 设备 → 手机 | 完整 ADV_IND PDU body |
| `rsp:<hex>` | 设备 → 手机 | 完整 SCAN_RSP PDU body |
| `con:<hex>` | 手机 → 设备 | CONNECT_IND PDU body |
| `dat:<event_hex>:<pdu_hex>` | 双向 | 带 event counter 的数据 PDU |

## 抓包分析

两个中继脚本均支持 PCAP 输出（`-o` 参数），可在 Wireshark 中离线分析：

```bash
# 设备侧抓包
python relay_central.py -B broker.example.com -t AA:BB:CC:DD:EE:FF -s /dev/ttyACM0 -o device_capture.pcapng

# 手机侧抓包
python relay_peripheral.py -B broker.example.com -s /dev/ttyACM1 -o peripheral_capture.pcapng
```

## 故障排查

| 现象 | 可能原因 | 解决方案 |
|------|----------|----------|
| "Waiting for advertisement data..." 一直挂起 | 设备侧未启动或 broker 不可达 | 检查 broker 连通性；先启动设备侧 |
| 手机侧看不到手机连接 | 手机不在范围内，或广播数据不正确 | 确保手机蓝牙扫描开启；检查目标 MAC |
| "HW packet error" 消息 | Sniffle 固件问题或 USB 断开 | 重新插拔开发板，重新刷固件 |
| Linux 串口 "resource busy" | ModemManager 正在探测串口设备 | `sudo systemctl stop ModemManager && sudo systemctl disable ModemManager` |
| 高延迟/丢包 | 到 broker 的网络延迟过大 | 使用地理位置靠近两个节点的 broker |

## 限制

- 仅支持传统广播（ADV_IND + SCAN_RSP），不支持扩展广播
- 中继延迟取决于到 MQTT broker 的网络往返时间
- 不处理 BLE 加密（攻击者必须在配对/绑定之前中继）
- 同时仅支持单连接

## 致谢

- [Sniffle](https://github.com/nccgroup/Sniffle) — Sultan Qasim Khan (NCC Group) 开发的 BLE 嗅探框架
- MQTT 传输方案，将 BLE 中继范围扩展到局域网之外

## 许可证

本项目基于 GNU General Public License v3.0 许可 — 详见 [LICENSE](LICENSE)。

本项目是基于 Sniffle (GPLv3) 的衍生作品。

## 免责声明

本工具仅供授权的安全研究和测试使用。用户有责任遵守所有适用法律。请勿对未拥有或未获得明确书面授权的系统使用此工具。
