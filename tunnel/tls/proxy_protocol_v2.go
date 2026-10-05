package tls

import (
	"bytes"
	"io"
	"net"

	"github.com/p4gefau1t/trojan-go/common"
)

// proxyConn 覆盖 RemoteAddr，用 Proxy 头中的真实 client 地址替换
type proxyConn struct {
	net.Conn
	remote net.Addr
}

func (p *proxyConn) RemoteAddr() net.Addr {
	return p.remote
}

// rewindConn 用于“可选 Proxy”场景：
// 已经从底层 Conn 读出了一部分数据（例如 16 字节），如果判断不是 Proxy v2，
// 就用这个连接把那部分数据“吐回去”，上层看起来就像什么都没读过一样。
type rewindConn struct {
	net.Conn
	buf []byte
}

func (r *rewindConn) Read(p []byte) (int, error) {
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}
	return r.Conn.Read(p)
}

const (
	proxyV2Sig      = "\r\n\r\n\000\r\nQUIT\n"
	maxProxyV2Len   = 512 // 限制一下地址+TLV部分长度，防止恶意超大
)

// parseProxyProtocolV2 实现“可选 Proxy Protocol v2”
//
// 行为：
//   1. 尝试读取 16 字节头部：
//      - 如果不是合法的 Proxy v2 头 → 返回一个 rewindConn，把 16 字节还回去，当普通 TLS 流量处理
//      - 如果是合法的 Proxy v2 头 → 继续读取地址部分，解析 src IP/port，返回 proxyConn 覆盖 RemoteAddr
//   2. 如果是合法 v2 但内容不合规（长度太短/太长等）→ 返回 error，调用方应关闭连接。
func parseProxyProtocolV2(conn net.Conn) (net.Conn, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	// 探测：不是 Proxy v2 就直接回退，走普通 TLS
	if !bytes.Equal(header[:12], []byte(proxyV2Sig)) || header[12]>>4 != 0x2 {
		// 非 Proxy v2：返回带回放缓冲的 Conn
		return &rewindConn{
			Conn: conn,
			buf:  header,
		}, nil
	}

	// 到这里说明：是 Proxy Protocol v2 头
	verCmd := header[12]
	cmd := verCmd & 0x0F // 0x01 = PROXY, 0x00 = LOCAL
	famProto := header[13]
	addrLen := int(header[14])<<8 | int(header[15])

	if addrLen < 0 || addrLen > maxProxyV2Len {
		return nil, common.NewError("proxy protocol v2 address too long")
	}

	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(conn, addrBuf); err != nil {
		return nil, err
	}

	// 缺省 remoteAddr：如果 header 类型不认识，就保留原 IP
	remoteAddr := conn.RemoteAddr()

	// LOCAL 命令：不使用 header 中的地址信息，但要吃掉 header，保持连接后续正常
	if cmd != 0x1 {
		return &proxyConn{
			Conn:   conn,
			remote: remoteAddr,
		}, nil
	}

	family := famProto >> 4
	proto := famProto & 0x0F

	// 只处理 TCP 流（STREAM），UDP 在当前 trojan-go 场景里暂不支持 Proxy Protocol
	if proto == 0x1 { // STREAM = TCP
		switch family {
		case 0x1: // INET (IPv4)
			// spec: srcAddr(4) + dstAddr(4) + srcPort(2) + dstPort(2) = 12 字节
			if addrLen < 12 {
				return nil, common.NewError("invalid ipv4 address length in proxy protocol v2")
			}
			srcIP := net.IP(addrBuf[0:4])
			srcPort := int(addrBuf[8])<<8 | int(addrBuf[9])
			remoteAddr = &net.TCPAddr{
				IP:   srcIP,
				Port: srcPort,
			}
		case 0x2: // INET6 (IPv6)
			// spec: srcAddr(16) + dstAddr(16) + srcPort(2) + dstPort(2) = 36 字节
			if addrLen < 36 {
				return nil, common.NewError("invalid ipv6 address length in proxy protocol v2")
			}
			srcIP := net.IP(addrBuf[0:16])
			srcPort := int(addrBuf[32])<<8 | int(addrBuf[33])
			remoteAddr = &net.TCPAddr{
				IP:   srcIP,
				Port: srcPort,
			}
		}
	}

	return &proxyConn{
		Conn:   conn,
		remote: remoteAddr,
	}, nil
}
