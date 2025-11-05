#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // 初始化缓冲区
    buf_t txbuf;
    buf_init(&txbuf, sizeof(arp_pkt_t));
    //填写ARP报头
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    // 复制初始ARP包的基本信息
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    // 设置操作类型为ARP_REQUEST，并进行大小端转换
    arp_pkt->opcode16 = swap16(ARP_REQUEST);
    // 设置目标IP地址
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    //发送 ARP 报文
    uint8_t broadcast_mac[NET_MAC_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    ethernet_out(&txbuf, broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // Step1. 初始化缓冲区：
    buf_t txbuf;
    buf_init(&txbuf, sizeof(arp_pkt_t));
    
    // Step2. 填写 ARP 报头首部：
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    
    // 复制初始ARP包的基本信息
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    
    // 设置操作类型为ARP_REPLY，并进行大小端转换
    arp_pkt->opcode16 = swap16(ARP_REPLY);
    
    // 设置目标IP和MAC地址（请求方的地址）
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(arp_pkt->target_mac, target_mac, NET_MAC_LEN);

    // 使用目标MAC地址（请求方的MAC）发送ARP响应
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // Step1. 检查数据长度：
    if (buf->len < sizeof(arp_pkt_t)) {
        // 数据包不完整，丢弃
        return;
    }

    // Step2. 报头检查：
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    
    // 检查硬件类型（以太网）
    if (swap16(arp_pkt->hw_type16) != ARP_HW_ETHER) {
        return;
    }
    
    // 检查上层协议类型（IP）
    if (swap16(arp_pkt->pro_type16) != NET_PROTOCOL_IP) {
        return;
    }
    
    // 检查MAC地址长度
    if (arp_pkt->hw_len != NET_MAC_LEN) {
        return;
    }
    
    // 检查IP地址长度
    if (arp_pkt->pro_len != NET_IP_LEN) {
        return;
    }
    
    // 检查操作类型（请求或响应）
    uint16_t opcode = swap16(arp_pkt->opcode16);
    if (opcode != ARP_REQUEST && opcode != ARP_REPLY) {
        return;
    }

    // Step3. 更新 ARP 表项：
    // 无论请求还是响应，都包含发送方的IP-MAC映射，需要更新ARP表
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);

    // Step4. 查看缓存情况：
    buf_t *cached_buf = (buf_t *)map_get(&arp_buf, arp_pkt->sender_ip);
    
    if (cached_buf != NULL) {
        // 有缓存情况：说明有等待该IP的数据包
        // 将缓存的数据包发送给以太网层
        ethernet_out(cached_buf, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        
        // 删除这个缓存的数据包
        map_delete(&arp_buf, arp_pkt->sender_ip);
    } else {
        // 无缓存情况：
        // 检查是否为请求本机MAC地址的ARP请求
        if (opcode == ARP_REQUEST) {
            // 比较目标IP是否为本机IP
            if (memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
                // 是请求本机MAC地址的ARP请求，回应ARP响应
                arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
            }
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // Step1. 查找 ARP 表：
    uint8_t *target_mac = (uint8_t *)map_get(&arp_table, ip);
    
    // Step2. 找到对应 MAC 地址：
    if (target_mac != NULL) {
        // 如果ARP表中已有该IP对应的MAC地址，直接发送数据包
        ethernet_out(buf, target_mac, NET_PROTOCOL_IP);
        return;
    }
    
    // Step3. 未找到对应 MAC 地址：
    // 检查arp_buf中是否已经有等待该IP的数据包
    buf_t *cached_buf = (buf_t *)map_get(&arp_buf, ip);
    
    if (cached_buf != NULL) {
        // 如果已经有包在等待该IP的ARP响应，说明已经发送过ARP请求
        // 此时不能再发送新的ARP请求，只需等待响应即可
        return;
    } else {
        // 如果没有包在等待，缓存当前数据包并发送ARP请求
        // 将数据包缓存到arp_buf中
        map_set(&arp_buf, ip, buf);
        
        // 发送ARP请求来查询目标IP的MAC地址
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}