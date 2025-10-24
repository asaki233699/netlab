#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // Step 1: 数据长度检查
    // 检查数据长度是否小于以太网头部长度，如果小于则丢弃数据包
    if (buf->len < sizeof(ether_hdr_t)) {
        return; // 数据包不完整，丢弃
    }
    
    // Step 2: 移除以太网包头
    // 先提取以太网头部信息，然后移除头部
    ether_hdr_t *ether_hdr = (ether_hdr_t *)buf->data;
    uint16_t protocol = swap16(ether_hdr->protocol16); // 转换为主机字节序
    uint8_t *src_mac = ether_hdr->src; // 源MAC地址
    
    // 移除以太网头部
    buf_remove_header(buf, sizeof(ether_hdr_t));
    
    // Step 3: 向上层传递数据包
    // 调用net_in函数向上层传递数据包
    net_in(buf, protocol, src_mac);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {

    // 检查数据长度是否不足46字节，如果不足则填充0
    if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT) {
        buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - buf->len);
    }
    
    // 为数据包添加以太网头部空间
    buf_add_header(buf, sizeof(ether_hdr_t));
    
    //填充以太网头部信息
    ether_hdr_t *ether_hdr = (ether_hdr_t *)buf->data;
    
    // 设置目标MAC地址
    memcpy(ether_hdr->dst, mac, NET_MAC_LEN);
    
    // 设置源MAC地址（本机MAC地址）
    memcpy(ether_hdr->src, net_if_mac, NET_MAC_LEN);
    
    // 设置协议类型（网络字节序）
    ether_hdr->protocol16 = swap16(protocol);
    
    // Step 4: 发送以太网帧
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
