#include "ip.h"
#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    if (buf->len < sizeof(ip_hdr_t)) {
        return;
    }

    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    
    // 版本检查
    if (ip_hdr->version != 4) {
        return;
    }

    // 头部长度检查
    uint16_t hdr_len = ip_hdr->hdr_len * 4;
    if (hdr_len < sizeof(ip_hdr_t)) {
        return;
    }
    
    // 总长度检查
    uint16_t total_len = swap16(ip_hdr->total_len16);
    if (total_len > buf->len) {
        return;
    }

    // 校验和检查
    uint16_t saved_checksum = swap16(ip_hdr->hdr_checksum16);  // 转换为主机字节序
    ip_hdr->hdr_checksum16 = 0;
    uint16_t calculated_checksum = checksum16((uint16_t *)ip_hdr, hdr_len);
    
    if (saved_checksum != calculated_checksum) {
        return;
    }
    ip_hdr->hdr_checksum16 = swap16(saved_checksum);  // 恢复为网络字节序

    // 目标IP检查
    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        return;
    }

    // 去除填充字段
    if (buf->len > total_len) {
        buf_remove_padding(buf, buf->len - total_len);
    }

    // 去掉IP报头
    buf_remove_header(buf, hdr_len);

    // 向上传递数据包
    int res = net_in(buf, ip_hdr->protocol, ip_hdr->src_ip);
    if (res == -1) {
        buf_add_header(buf, hdr_len);
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}

/**
 * @brief 处理一个要发送的ip分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    buf_add_header(buf, sizeof(ip_hdr_t));

    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    ip_hdr->version = 4;
    ip_hdr->hdr_len = 5;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->id16 = swap16(id);
    
    uint16_t flags_fragment = 0;
    flags_fragment |= (offset & 0x1FFF);  // 13位偏移量，offset已经是除以8后的值
    if (mf) {
        flags_fragment |= 0x2000;  // MF标志
    }
    ip_hdr->flags_fragment16 = swap16(flags_fragment);
    
    ip_hdr->ttl = 64;
    ip_hdr->protocol = protocol;
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);

    // 重新计算校验和
    ip_hdr->hdr_checksum16 = 0;
    ip_hdr->hdr_checksum16 = swap16(checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t)));

    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    static uint16_t identification = 0;
    const uint16_t MAX_PAYLOAD = 1480;

    if (buf->len > MAX_PAYLOAD) {
        // 需要分片
        uint16_t offset = 0;
        uint16_t remain_len = buf->len;

        while (remain_len > 0) {
            buf_t ip_buf;
            buf_init(&ip_buf, 0);

            // 计算分片长度
            uint16_t fragment_len = (remain_len > MAX_PAYLOAD) ? MAX_PAYLOAD : remain_len;

            // 复制数据
            buf_add_header(&ip_buf, fragment_len);
            memcpy(ip_buf.data, buf->data + offset, fragment_len);

            // 计算偏移量
            uint16_t fragment_offset = offset/8;

            // 设置MF标志
            int mf = (remain_len > fragment_len) ? 1 : 0;

            // 发送分片
            ip_fragment_out(&ip_buf, ip, protocol, identification, fragment_offset, mf);

            offset += fragment_len;
            remain_len -= fragment_len;
        }
        identification++;
    } else {
        // 不需要分片
        buf_t ip_buf;
        buf_init(&ip_buf, 0);
        
        buf_add_header(&ip_buf, buf->len);
        memcpy(ip_buf.data, buf->data, buf->len);
        
        ip_fragment_out(&ip_buf, ip, protocol, identification, 0, 0);
        identification++;
    }
}

/**
 * @brief 初始化ip协议
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}