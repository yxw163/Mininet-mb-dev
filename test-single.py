#!/usr/bin/python
# encoding: utf-8

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel


class SingleSwitchTopo(Topo):

    def __init__(self, n=2, **opts):
        Topo.__init__(self, **opts)

        #Add hosts, middleboxes and switches
        leftHost = self.addHost( 'h1' )
        rightHost = self.addHost( 'h2' )
        mb = self.addMiddleBox( 'm1' )
        topSwitch = self.addSwitch( 's1' )
        leftSwitch = self.addSwitch( 's2' )
        rightSwitch = self.addSwitch( 's3' )

        # Add links
        self.addLink( topSwitch, leftSwitch )
        self.addLink( topSwitch, rightSwitch )
        self.addLink( leftSwitch, leftHost )
        self.addLink( leftSwitch, rightHost )
        self.addLinkPair( rightSwitch, mb )

topos = { 'mbtopo': ( lambda: MiddleBoxTopo() ) }

def simpleTest():
    topo = SingleSwitchTopo(n=2)
    net = Mininet(topo)  # 主要类来创建和管理网络
    net.start()		# 启动您的拓扑网络
    print('Dumping host connections')
    dumpNodeConnections(net.hosts)		# 转存文件连接
    print('Testing network connectivity')
    net.pingAll()		# 所有节点彼此测试互连
    net.stop()		# 停止您的网络

if __name__ == '__main__':
    setLogLevel('info')		# 设置 Mininet 默认输出级别，设置 info 它将提供一些有用的信息
    # simpleTest()
