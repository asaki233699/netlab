#include "udp.h"

#include "icmp.h"
#include "ip.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip) {
    // 包检查
    if (buf->len<sizeof(udp_hdr_t)){
        return;
    }

    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;
    uint16_t total_len = swap16(hdr->total_len16);
    if (buf->len < total_len){
        return;
    }

    //重新计算校验和
    uint16_t received_checksum = swap16(hdr->checksum16);  // 转换为主机字节序
    hdr->checksum16 = 0;
    uint16_t new_checksum = transport_checksum(NET_PROTOCOL_UDP,buf,src_ip,net_if_ip);
    hdr->checksum16 = swap16(received_checksum);  // 恢复为网络字节序
    if (received_checksum != 0 && new_checksum != received_checksum) {
        return;
    }

    // 查询处理函数
    uint16_t dst_port = swap16(hdr->dst_port16);
    uint16_t src_port = swap16(hdr->src_port16);  // 在移除头部前保存src_port
    udp_handler_t *handler_ptr = (udp_handler_t *)map_get(&udp_table, &dst_port);

    //处理未找到处理函数的情况
    if (handler_ptr == NULL){
        // 增加IP头部用于ICMP差错报文
        if (buf_add_header(buf, sizeof(ip_hdr_t)) == 0) {
            // 发送端口不可达ICMP差错报文
            icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
        }
        return;
    }

    //调用处理函数
    buf_remove_header(buf,sizeof(udp_hdr_t));

    udp_handler_t handler = *handler_ptr;
    handler(buf->data, buf->len, src_ip, src_port);
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    // Step1: 添加UDP报头
    if (buf_add_header(buf, sizeof(udp_hdr_t)) != 0) {
        return;
    }

    // Step2: 填充UDP首部字段
    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;
    hdr->src_port16 = swap16(src_port);
    hdr->dst_port16 = swap16(dst_port);
    hdr->total_len16 = swap16(buf->len);
    hdr->checksum16 = 0;  // 先置0，用于校验和计算

    // Step3: 计算并填充校验和
    uint16_t checksum = transport_checksum(NET_PROTOCOL_UDP, buf, net_if_ip, dst_ip);
    // 重新获取hdr指针，因为transport_checksum可能修改了buf->data
    hdr = (udp_hdr_t *)buf->data;
    hdr->checksum16 = swap16(checksum);

    // Step4: 发送UDP数据报
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init() {
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler) {
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port) {
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}