package main

import (
	"errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nxsre/qemu-vmnet/vmnet"
)

func main() {
	enc := zap.NewProductionEncoderConfig()
	enc.EncodeTime = zapcore.ISO8601TimeEncoder
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(enc),
		zapcore.Lock(os.Stdout),
		zap.NewAtomicLevelAt(zap.InfoLevel),
	), zap.AddCaller())
	defer logger.Sync() // flushes buffer, if any
	sugar := logger.Sugar()

	vmn := vmnet.New()
	if err := vmn.Start(); err != nil {
		sugar.Fatalf("unable to start vmnet interface, please try again with [sudo]")
		return
	}
	defer vmn.Stop()

	conn, err := net.ListenPacket("udp", ":2235")
	if err != nil {
		sugar.Fatalf("unable to start the listener, %s", err.Error())
		return
	}
	defer conn.Close()

	// 写数据到 vmnet 的 channel
	writeToVNNetChan := make(chan []byte)
	// qemu clients
	clients := map[string]net.Addr{}
	// client arp 表
	clients_arp := map[string]string{}
	// 从 vmnet 读取数据
	go func() {
		for {
			bytes := make([]byte, vmn.MaxPacketSize)
			bytesLen, err := vmn.Read(bytes)
			if err != nil {
				sugar.Infof("error while reading from vmnet: %s", err.Error())
				continue
			}

			bytes = bytes[:bytesLen]
			sugar.Debugf("received %d bytes from vmnet", bytesLen)

			go func(bytes []byte) {
				pkt := gopacket.NewPacket(bytes, layers.LayerTypeEthernet, gopacket.Default)
				sugar.Debugf("%s", pkt.String())

				layer := pkt.Layer(layers.LayerTypeEthernet)
				if layer == nil {
					return
				}

				ethLayer, _ := layer.(*layers.Ethernet)
				destinationMAC := ethLayer.DstMAC.String()

				ipLayer := pkt.Layer(layers.LayerTypeIPv4)
				ip, _ := ipLayer.(*layers.IPv4)
				if ip != nil {
					sugar.Debugf("dstIP: %s", ip.DstIP)
				}

				arpLayer := pkt.Layer(layers.LayerTypeARP)
				arp, _ := arpLayer.(*layers.ARP)
				if arp != nil {
					sugar.Debugf("src mac: %v, src ip: %v", net.HardwareAddr(arp.SourceHwAddress), net.IP(arp.SourceProtAddress))
					_, exist := clients_arp[net.IP(arp.SourceProtAddress).String()]
					if !exist {
						ip := net.IP(arp.SourceProtAddress).String()
						mac := net.HardwareAddr(arp.SourceHwAddress).String()
						clients_arp[ip] = mac
						sugar.Infof("new client arp pairs ip:%s => mac:%s", ip, mac)
					}

					// 发 arp 广播
					for destinationMAC, addr := range clients {
						if _, err := conn.WriteTo(bytes, addr); err != nil {
							if errors.Is(err, net.ErrClosed) {
								delete(clients, destinationMAC)
								sugar.Infof("deleted client with mac %s", destinationMAC)
								return
							}
							sugar.Errorf("error while writing to %s: %s", addr.String(), err.Error())
						}
					}
				}

				addr, exist := clients[destinationMAC]
				if !exist {
					return
				}

				sugar.Infof("writing %d bytes to %s", len(bytes), addr.String())

				if _, err := conn.WriteTo(bytes, addr); err != nil {
					if errors.Is(err, net.ErrClosed) {
						delete(clients, destinationMAC)
						sugar.Infof("deleted client with mac %s", destinationMAC)
						return
					}

					sugar.Errorf("error while writing to %s: %s", addr.String(), err.Error())
					return
				}
			}(bytes)
		}
	}()

	// 从 writeToVNNetChan 读数据并写入到 vmnet
	go func() {
		for {
			bytes := <-writeToVNNetChan

			sugar.Infof("writing %d bytes to vmnet", len(bytes))

			if _, err := vmn.Write(bytes); err != nil {
				sugar.Errorf("error while writing to vmnet: %s", err.Error())
				continue
			}
		}
	}()

	// 从 qemu 的连接读取数据
	go func() {
		for {
			bytes := make([]byte, vmn.MaxPacketSize)
			bytesLen, addr, err := conn.ReadFrom(bytes)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break
				}

				sugar.Errorf("error while reading from %s: %s", addr.String(), err.Error())
				continue
			}

			bytes = bytes[:bytesLen]
			pkt := gopacket.NewPacket(bytes, layers.LayerTypeEthernet, gopacket.Default)

			sugar.Debugf("received %d bytes from %s", bytesLen, addr.String())
			sugar.Debugf("%s", pkt.String())

			if layer := pkt.Layer(layers.LayerTypeEthernet); layer != nil {
				eth, _ := layer.(*layers.Ethernet)

				_, exist := clients[eth.SrcMAC.String()]
				if !exist {
					clients[eth.SrcMAC.String()] = addr
					sugar.Infof("new client with mac %s", eth.SrcMAC.String())
				}

				// 判断是否 IPv4
				ipLayer := pkt.Layer(layers.LayerTypeIPv4)
				ip, _ := ipLayer.(*layers.IPv4)
				if ip != nil {
					sugar.Infof("srcIP: %v, dstIP: %v", ip.SrcIP, ip.DstIP)
					destinationMAC, arpExist := clients_arp[ip.DstIP.String()]
					if arpExist {
						addr, exist := clients[destinationMAC]
						if exist {
							if _, err := conn.WriteTo(bytes, addr); err != nil {
								if errors.Is(err, net.ErrClosed) {
									delete(clients, destinationMAC)
									sugar.Infof("deleted client with mac %s", destinationMAC)
									return
								}

								sugar.Errorf("error while writing to %s: %s", addr.String(), err.Error())
							}
							continue
						}
					}
				}

				// 判断是否 arp
				arpLayer := pkt.Layer(layers.LayerTypeARP)
				arp, _ := arpLayer.(*layers.ARP)
				if arp != nil {
					sugar.Debugf("src mac: %v, src ip: %v", net.HardwareAddr(arp.SourceHwAddress), net.IP(arp.SourceProtAddress))
					_, exist := clients_arp[net.IP(arp.SourceProtAddress).String()]
					if !exist {
						ip := net.IP(arp.SourceProtAddress).String()
						mac := net.HardwareAddr(arp.SourceHwAddress).String()
						clients_arp[ip] = mac
						sugar.Infof("new client arp pairs ip:%s => mac:%s", ip, mac)
					}

					// 发 arp 广播
					for destinationMAC, addr := range clients {
						if _, err := conn.WriteTo(bytes, addr); err != nil {
							if errors.Is(err, net.ErrClosed) {
								delete(clients, destinationMAC)
								sugar.Infof("deleted client with mac %s", destinationMAC)
								return
							}
							sugar.Errorf("error while writing to %s: %s", addr.String(), err.Error())
						}
					}
				}
				writeToVNNetChan <- bytes
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
