from optparse import OptionParser
from mininet.node import ( Host, CPULimitedHost, Controller, OVSController,
						   Ryu, NOX, RemoteController, findController,
						   DefaultController, NullController,
						   UserSwitch, OVSSwitch, OVSBridge,
						   IVSSwitch )
from mininet.nodelib import LinuxBridge
from mininet.topo import ( SingleSwitchTopo, LinearTopo,
						   SingleSwitchReversedTopo, MinimalTopo )
from mininet.topolib import TreeTopo, TorusTopo
from mininet.util import customClass, specialClass, splitArgs

CONTROLLERDEF = 'default'
CONTROLLERS = { 'ref': Controller,
				'ovsc': OVSController,
				'nox': NOX,
				'remote': RemoteController,
				'ryu': Ryu,
				'default': DefaultController,  # Note: overridden below
				'none': NullController }

SWITCHDEF = 'default'
SWITCHES = { 'user': UserSwitch,
			 'ovs': OVSSwitch,
			 'ovsbr' : OVSBridge,
			 # Keep ovsk for compatibility with 2.0
			 'ovsk': OVSSwitch,
			 'ivs': IVSSwitch,
			 'lxbr': LinuxBridge,
			 'default': OVSSwitch }

TOPODEF = 'minimal'
TOPOS = { 'minimal': MinimalTopo,
		  'linear': LinearTopo,
		  'reversed': SingleSwitchReversedTopo,
		  'single': SingleSwitchTopo,
		  'tree': TreeTopo,
		  'torus': TorusTopo }

HOSTDEF = 'proc'
HOSTS = { 'proc': Host,
          'rt': specialClass( CPULimitedHost, defaults=dict( sched='rt' ) ),
          'cfs': specialClass( CPULimitedHost, defaults=dict( sched='cfs' ) ) }

def parseArgs():
		"""Parse command-line args and return options object.
		   returns: opts parse options dict"""

		desc = ( "The %prog utility creates Mininet network from the\n"
				 "command line. It can create parametrized topologies,\n"
				 "invoke the Mininet CLI, and run tests." )

		usage = ( '%prog [options]\n'
				  '(type %prog -h for details)' )

		opts = OptionParser( description=desc, usage=usage )
		opts.add_option( '--clean', '-c', action='store_true',
						 default=False, help='clean and exit' )

		addDictOption( opts, CONTROLLERS, [], 'controller', action='append' )
		addDictOption( opts, SWITCHES, SWITCHDEF, 'switch' )
		addDictOption( opts, TOPOS, TOPODEF, 'topo' )
		addDictOption( opts, HOSTS, HOSTDEF, 'host' )
		options, args = opts.parse_args()
		opts.print_help()
		print(options)
		

def addDictOption( opts, choicesDict, default, name, **kwargs ):
	"""Convenience function to add choices dicts to OptionParser.
	   opts: OptionParser instance
	   choicesDict: dictionary of valid choices, must include default
	   default: default choice key
	   name: long option name
	   kwargs: additional arguments to add_option"""
	helpStr = ( '|'.join( sorted( choicesDict.keys() ) ) +
				'[,param=value...]' )
	helpList = [ '%s=%s' % ( k, v.__name__ )
				 for k, v in choicesDict.items() ]
	helpStr += ' ' + ( ' '.join( helpList ) )
	params = dict( type='string', default=default, help=helpStr )
	params.update( **kwargs )
	opts.add_option( '--' + name, **params )

def ipAdd( i, prefixLen=8, ipBaseNum=0x0a000000 ):
    """Return IP address string from ints
       i: int to be added to ipbase
       prefixLen: optional IP prefix length
       ipBaseNum: option base IP address as int
       returns IP address as string"""
    imax = 0xffffffff >> prefixLen
    assert i <= imax, 'Not enough IP addresses in the subnet'
    mask = 0xffffffff ^ imax
    ipnum = ( ipBaseNum & mask ) + i
    return ipStr( ipnum )

def ipStr( ip ):
    """Generate IP address string from an unsigned int.
       ip: unsigned int of form w << 24 | x << 16 | y << 8 | z
       returns: ip address string w.x.y.z"""
    w = ( ip >> 24 ) & 0xff
    x = ( ip >> 16 ) & 0xff
    y = ( ip >> 8 ) & 0xff
    z = ip & 0xff
    return "%i.%i.%i.%i" % ( w, x, y, z )

if __name__ == '__main__':
	# parseArgs()
	print(ipAdd(2))


                                                                                                                                                                                                                                              01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=vvirtuale box x[?1l>
]2;virtualbox]1;virtualbox

^C
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=[?1l>
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=[?1l>
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;lsCONTRIBUTORS      [1m[36mbin[39;49m[0m               [1m[36mexamples[39;49m[0m          test.py
INSTALL           code.py           [1m[36mmininet[39;49m[0m           test1.py
LICENSE           [1m[36mcustom[39;49m[0m            mnexec.c          topo-2sw-2host.py
Makefile          [1m[36mdebian[39;49m[0m            setup.py          typescript
README.md         [1m[36mdoc[39;49m[0m               test-single.py    [1m[36mutil[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=[?1l>
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=[?1l>
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ppython    p  s ppython test
[J[0mtest-single.py  [Jtest.py         [Jtest1.py      [J[A[0m[27m[24m[26Cpython test[K-single.py[1m [0m[0m [?1l>
[J]2;python test-single.py]1;python  File "test-single.py", line 13
SyntaxError: Non-ASCII character '\xe6' in file test-single.py on line 13, but no encoding declared; see http://python.org/dev/peps/pep-0263/ for details
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=pps -ef|grep test
[J[0mtest-single.py  [Jtest.py         [Jtest1.py      [J[A[0m[27m[24m[26Cps -ef|grep test[K*[?1l>
[J]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} test*]1;ps[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=pps -ef|grep test-single.py[?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501  6407   526   0  9:35上午 ??        26:52.27 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501  6772   526   0  9:52上午 ??        10:21.92 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501  7316   526   0  9:57上午 ??         4:39.25 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501  7656   526   0 10:02上午 ??         0:20.23 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501  7940  1314   0 10:02上午 ttys003    0:00.00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn [01;31m[Ktest-single.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=kkill -9 6407 6772 7316 7656[?1l>
]2;kill -9 6407 6772 7316 7656]1;kill[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=kill -9 6407 6772 7316 7656[27Dps -ef|grep test-single.py [?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501  7960  1314   0 10:03上午 ttys003    0:00.00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn [01;31m[Ktest-single.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=kkil -9  l -9 7960[?1l>
]2;kill -9 7960]1;killkill: kill 7960 failed: no such process
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=[?1l>
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=[?1l>
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=[?1l>
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=kill -9 7960[12Dps -ef|grep test-single.py[?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501  8007   526   0 10:03上午 ??         1:05.78 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501  8276   526   0 10:04上午 ??         0:43.42 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=kkill -9 8007 8276[?1l>
]2;kill -9 8007 8276]1;kill[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;lsCONTRIBUTORS      [1m[36mbin[39;49m[0m               [1m[36mexamples[39;49m[0m          test.py
INSTALL           code.py           [1m[36mmininet[39;49m[0m           test1.py
LICENSE           [1m[36mcustom[39;49m[0m            mnexec.c          topo-2sw-2host.py
Makefile          [1m[36mdebian[39;49m[0m            setup.py          typescript
README.md         [1m[36mdoc[39;49m[0m               test-single.py    [1m[36mutil[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ppwd[?1l>
]2;pwd]1;pwd/Users/yangxw/learn_python/Mininet/mininet
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ssudo inst
[0minstall            install_name_tool  instmodsh          instmodsh5.18    
[Jinstall-info       [Jinstaller          [Jinstmodsh5.16      [Jinstruments      [J[A[A[0m[27m[24m[26Csudo inst[Kall
[J[J[0minstall            [Jinstall-info       [Jinstall_name_tool  [Jinstaller        [J[A[0m[27m[24m[26Csudo install[K -a[?1l>
[J]2;sudo install -a]1;installPassword:
install: illegal option -- a
usage: install [-bCcpSsv] [-B suffix] [-f flags] [-g group] [-m mode]
               [-o owner] file1 file2
       install [-bCcpSsv] [-B suffix] [-f flags] [-g group] [-m mode]
               [-o owner] file1 ... fileN directory
       install -d [-v] [-g group] [-m mode] [-o owner] directory ...
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccd ..  c  ccd cunst[?1l>
]2;cd cunst]1;cdcd: no such file or directory: cunst
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccd cuns  stom[1m/[0m[0m [?1l>
]2;cd custom]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet/custom]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/custom[0m[27m[24m[J[01;32m➜  [36mcustom[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;lsREADME
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet/custom]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/custom[0m[27m[24m[J[01;32m➜  [36mcustom[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccd ..[?1l>
]2;cd ..]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;lsCONTRIBUTORS      [1m[36mbin[39;49m[0m               [1m[36mexamples[39;49m[0m          test.py
INSTALL           code.py           [1m[36mmininet[39;49m[0m           test1.py
LICENSE           [1m[36mcustom[39;49m[0m            mnexec.c          topo-2sw-2host.py
Makefile          [1m[36mdebian[39;49m[0m            setup.py          typescript
README.md         [1m[36mdoc[39;49m[0m               test-single.py    [1m[36mutil[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccat c  ppython setup.py[1m [0m[0m [?1l>
]2;python setup.py]1;pythonTraceback (most recent call last):
  File "setup.py", line 11, in <module>
    from mininet.net import VERSION
  File "/Users/yangxw/learn_python/Mininet/mininet/mininet/net.py", line 99, in <module>
    from mininet.cli import CLI
  File "/Users/yangxw/learn_python/Mininet/mininet/mininet/cli.py", line 31, in <module>
    from select import poll, POLLIN
ImportError: cannot import name poll
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=python setup.py[15D               [15Dpython setup.py install[?1l>
]2;python setup.py install]1;pythonTraceback (most recent call last):
  File "setup.py", line 11, in <module>
    from mininet.net import VERSION
  File "/Users/yangxw/learn_python/Mininet/mininet/mininet/net.py", line 99, in <module>
    from mininet.cli import CLI
  File "/Users/yangxw/learn_python/Mininet/mininet/mininet/cli.py", line 31, in <module>
    from select import poll, POLLIN
ImportError: cannot import name poll
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;lsCONTRIBUTORS      [1m[36mbin[39;49m[0m               [1m[36mexamples[39;49m[0m          test.py
INSTALL           code.py           [1m[36mmininet[39;49m[0m           test1.py
LICENSE           [1m[36mcustom[39;49m[0m            mnexec.c          topo-2sw-2host.py
Makefile          [1m[36mdebian[39;49m[0m            setup.py          typescript
README.md         [1m[36mdoc[39;49m[0m               test-single.py    [1m[36mutil[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccd bin[?1l>
]2;cd bin]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..t/mininet/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/bin[0m[27m[24m[J[01;32m➜  [36mbin[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;ls[31mmn[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..t/mininet/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/bin[0m[27m[24m[J[01;32m➜  [36mbin[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=w ppwd[?1l>
]2;pwd]1;pwd/Users/yangxw/learn_python/Mininet/mininet/bin
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..t/mininet/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/bin[0m[27m[24m[J[01;32m➜  [36mbin[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=//Users/yangxw/learn_python/Mininet/mininet/bin mn[?1l>
]2;/Users/yangxw/learn_python/Mininet/mininet/bin mn]1;/Users/yangxw/learn_python/Mininet/mininet/binzsh: permission denied: /Users/yangxw/learn_python/Mininet/mininet/bin
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..t/mininet/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/bin[0m[27m[24m[J[01;31m➜  [36mbin[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ssudo /Users/yangxw/learn_python/Mininet/mininet/bin/mn[?1l>
]2;sudo /Users/yangxw/learn_python/Mininet/mininet/bin/mn]1;/Users/yangxw/learn_python/Mininet/mininet/bin/mnTraceback (most recent call last):
  File "/Users/yangxw/learn_python/Mininet/mininet/bin/mn", line 23, in <module>
    from mininet.clean import cleanup
ImportError: No module named mininet.clean
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..t/mininet/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/bin[0m[27m[24m[J[01;31m➜  [36mbin[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;ls[31mmn[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..t/mininet/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/bin[0m[27m[24m[J[01;32m➜  [36mbin[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ssud s  ccd ..[?1l>
]2;cd ..]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;lsCONTRIBUTORS      [1m[36mbin[39;49m[0m               [1m[36mexamples[39;49m[0m          test.py
INSTALL           code.py           [1m[36mmininet[39;49m[0m           test1.py
LICENSE           [1m[36mcustom[39;49m[0m            mnexec.c          topo-2sw-2host.py
Makefile          [1m[36mdebian[39;49m[0m            setup.py          typescript
README.md         [1m[36mdoc[39;49m[0m               test-single.py    [1m[36mutil[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ssudo i In i int   INin  inst    INSTAinstall[?1l>
]2;sudo install]1;installusage: install [-bCcpSsv] [-B suffix] [-f flags] [-g group] [-m mode]
               [-o owner] file1 file2
       install [-bCcpSsv] [-B suffix] [-f flags] [-g group] [-m mode]
               [-o owner] file1 ... fileN directory
       install -d [-v] [-g group] [-m mode] [-o owner] directory ...
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=sudo install.install/install[1C[1C[1C[1C[1C[1C[1C -a[?1l>
]2;sudo ./install -a]1;./installsudo: ./install: command not found
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=sudo ./install -a. -as -ah -a[?1l>
]2;sudo ./install.sh -a]1;./install.shsudo: ./install.sh: command not found
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;31m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccd custom[1m/[0m[0m [?1l>
]2;cd custom]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet/custom]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/custom[0m[27m[24m[J[01;32m➜  [36mcustom[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;lsREADME
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet/custom]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/custom[0m[27m[24m[J[01;32m➜  [36mcustom[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccd ..[?1l>
]2;cd ..]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;lsCONTRIBUTORS      [1m[36mbin[39;49m[0m               [1m[36mexamples[39;49m[0m          test.py
INSTALL           code.py           [1m[36mmininet[39;49m[0m           test1.py
LICENSE           [1m[36mcustom[39;49m[0m            mnexec.c          topo-2sw-2host.py
Makefile          [1m[36mdebian[39;49m[0m            setup.py          typescript
README.md         [1m[36mdoc[39;49m[0m               test-single.py    [1m[36mutil[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccdm  mininet[1m/[0m[0m [?1l>
]2;cd mininet]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;ls__init__.py   cli.pyc       moduledeps.py term.py       util.py
__init__.pyc  [35mexamples[39;49m[0m      [31mnet.py[39;49m[0m        [1m[36mtest[39;49m[0m          util.pyc
[1m[36m__pycache__[39;49m[0m   link.py       net.pyc       topo.py
[31mclean.py[39;49m[0m      log.py        node.py       topo.pyc
cli.py        log.pyc       nodelib.py    topolib.py
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccd .[?1l>
]2;cd .]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccd ..[?1l>
]2;cd ..]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;lsCONTRIBUTORS      [1m[36mbin[39;49m[0m               [1m[36mexamples[39;49m[0m          test.py
INSTALL           code.py           [1m[36mmininet[39;49m[0m           test1.py
LICENSE           [1m[36mcustom[39;49m[0m            mnexec.c          topo-2sw-2host.py
Makefile          [1m[36mdebian[39;49m[0m            setup.py          typescript
README.md         [1m[36mdoc[39;49m[0m               test-single.py    [1m[36mutil[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccat InNSTALL[1m [0m[0m [?1l>
]2;cat INSTALL]1;cat
Mininet Installation/Configuration Notes
----------------------------------------

Mininet 2.3.0d1
---

The supported installation methods for Mininet are 1) using a
pre-built VM image, and 2) native installation on Ubuntu. You can also
easily create your own Mininet VM image (4).

(Other distributions may be supported in the future - if you would
like to contribute an installation script, we would welcome it!)

1. Easiest "installation" - use our pre-built VM image!

   The easiest way to get Mininet running is to start with one of our
   pre-built virtual machine images from <http://mininet.org/>

   Boot up the VM image, log in, and follow the instructions on the
   Mininet web site.

   One advantage of using the VM image is that it doesn't mess with
   your native OS installation or damage it in any way.

   Although a single Mininet instance can simulate multiple networks
   with multiple controllers, only one Mininet instance may currently
   be run at a time, and Mininet requires root access in the machine
   it's running on.  Therefore, if you have a multiuser system, you
   may wish to consider running Mininet in a VM.

2. Next-easiest option: use our Ubuntu package!

   To install Mininet itself (i.e. `mn` and the Python API) on Ubuntu
   12.10+:

        sudo apt-get install mininet

   Note: if you are upgrading from an older version of Mininet, make
   sure you remove the old OVS from `/usr/local`:

        sudo rm /usr/local/bin/ovs*
        sudo rm /usr/local/sbin/ovs*

3. Native installation from source

3.1. Native installation from source on Ubuntu 12.04+

   If you're reading this, you've probably already done so, but the
   command to download the Mininet source code is:

        git clone git://github.com/mininet/mininet.git

   Note that the above git command will check out the latest and greatest
   Mininet (which we recommend!) If you want to run the last tagged/released
   version of Mininet, you can look at the release tags using

        cd mininet
        git tag

    and then

        git checkout <release tag>

   where <release tag> is the release you want to check out.

   If you are running Ubuntu, Debian, or Fedora, you may be able to use
   our handy `install.sh` script, which is in `util/`.

   *WARNING: USE AT YOUR OWN RISK!*

   `install.sh` is a bit intrusive and may possibly damage your OS
   and/or home directory, by creating/modifying several directories
   such as `mininet`, `openflow`, `oftest`, `pox`, etc.. We recommend
   trying it in a VM before trying it on a system you use from day to day.

   Although we hope it won't do anything completely terrible, you may
   want to look at the script before you run it, and you should make
   sure your system and home directory are backed up just in case!

   To install Mininet itself, the OpenFlow reference implementation, and
   Open vSwitch, you may use:

        util/install.sh -fnv

   This should be reasonably quick, and the following command should
   work after the installation:

        sudo mn --test pingall

   To install ALL of the software which we use for OpenFlow tutorials,
   including POX, the OpenFlow WireShark dissector, the `oftest`
   framework, and other potentially useful software, you may use:

        util/install.sh -a

   This takes about 4 minutes on our test system.

   You can change the directory where the dependencies are installed using
   the -s <directory> flag.

        util/install.sh -s <directory> -a

3.2. Native installation from source on Fedora 18+.

   As root execute the following operations:

    * install git

        yum install git

    * create an user account (e.g. mininet) and add it to the wheel group

        useradd [...] mininet
        usermod -a -G wheel mininet

    * change the SElinux setting to permissive. It can be done
      temporarily with:

        setenforce 0

   then login with the new account (e.g. mininet) and do the following:

    * clone the Mininet repository

        git clone git://github.com/mininet/mininet.git

    * install Mininet, the OpenFlow reference implementation, and
      Open vSwitch

        util/install.sh -fnv

    * enable and start openvswitch

        sudo systemctl enable openvswitch
        sudo systemctl start openvswitch

    * test the mininet installation

        sudo mn --test pingall

4. Creating your own Mininet/OpenFlow tutorial VM

   Creating your own Ubuntu Mininet VM for use with the OpenFlow tutorial
   is easy! First, create a new Ubuntu VM. Next, run two commands in it:

        wget https://raw.github.com/mininet/mininet/master/util/vm/install-mininet-vm.sh
        time install-mininet-vm.sh

   Finally, verify that Mininet is installed and working in the VM:

        sudo mn --test pingall

5. Installation on other Linux distributions

   Although we don't support other Linux distributions directly, it
   should be possible to install and run Mininet with some degree of
   manual effort.

   In general, you must have:

   * A Linux kernel compiled with network namespace support enabled

   * An compatible software switch such as Open vSwitch or
     the Linux bridge.

   * Python, `bash`, `ping`, `iperf`, etc.

   * Root privileges (required for network device access)

   We encourage contribution of patches to the `install.sh` script to
   support other Linux distributions.


Good luck!

Mininet Team

---
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;lsCONTRIBUTORS      [1m[36mbin[39;49m[0m               [1m[36mexamples[39;49m[0m          test.py
INSTALL           code.py           [1m[36mmininet[39;49m[0m           test1.py
LICENSE           [1m[36mcustom[39;49m[0m            mnexec.c          topo-2sw-2host.py
Makefile          [1m[36mdebian[39;49m[0m            setup.py          typescript
README.md         [1m[36mdoc[39;49m[0m               test-single.py    [1m[36mutil[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccd util[1m/[0m[0m [?1l>
]2;cd util]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;32m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=lls[?1l>
]2;ls -G]1;ls[31mbuild-ovs-packages.sh[39;49m[0m [1m[36mkbuild[39;49m[0m                sysctl_addon
[31mclustersetup.sh[39;49m[0m       [31mm[39;49m[0m                     [31munpep8[39;49m[0m
colorfilters          [1m[36mnox-patches[39;49m[0m           [31mversioncheck.py[39;49m[0m
[31mdoxify.py[39;49m[0m             [1m[36mopenflow-patches[39;49m[0m      [1m[36mvm[39;49m[0m
[31minstall.sh[39;49m[0m            [1m[36msch_htb-ofbuf[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;32m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ssudo in    s  ssuto ./install.sh[1m [0m[0m i -a[?1l>
]2;suto ./install.sh -a]1;sutozsh: command not found: suto
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;31m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ssudo ./install.sh[1m [0m[0m -a[?1l>
]2;sudo ./install.sh -a]1;./install.shDetected Linux distribution: Unknown Unknown Unknown amd64
Install.sh currently only supports Ubuntu|Debian|Fedora|RedHatEnterpriseServer|SUSE LINUX.
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;31m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=uuname -m[?1l>
]2;uname -m]1;unamex86_64
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;32m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=uname -m[8Dsudo ./install.sh -a[18Dt[17C[20Dls                  [18Dcd utills     cat INSTALL[11Dls         [9Dcd .. ls  cd mininet[10Dls        [8Dcd ..ls   cd custom[9Dsudo ./install.sh -a -a   [12Dinstall     [12Dls          [10Dcd ..ls   sudo /Users/yangxw/learn_python/Mininet/mininet/bin/mn[54D[5P[46C [2C     [49Dsudo /Users/yangxw/learn_python/Mininet/mininet/bin/mn[54D[5P[46C [2C     [49Dpwd                                              [46Dls cd binls    python setup.py install       [8D[15Dls             [13Dcd ..ls   cd customnst [8Dsudo install -a[15Dpwd            [12Dls kill -9 8007 8276[17Dps -ef|grep test-single.py[26Dkill -9 7960              [14D[12Dps -ef|grep test-single.py[?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501  8961   526   0 10:11上午 ??         3:52.95 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501  9766   526   0 10:12上午 ??         2:33.24 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501 10038   526   0 10:14上午 ??         1:10.13 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501 10575   526   0 10:15上午 ??         0:20.60 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501 10845  1314   0 10:15上午 ttys003    0:00.00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn [01;31m[Ktest-single.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;32m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=kkill -9 8961 9766 10038 10575 10845[?1l>
]2;kill -9 8961 9766 10038 10575 10845]1;killkill: kill 10845 failed: no such process
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;31m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=kill -9 8961 9766 10038 10575 10845[35Dps -ef|grep test-single.py         [9D[26Duname -m                  [18D[8Dps -ef|grep test-single.py[?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501 10864   526   0 10:15上午 ??         2:30.68 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501 11134   526   0 10:16上午 ??         2:06.82 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501 11941   526   0 10:17上午 ??         0:37.90 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501 12478   526   0 10:18上午 ??         0:13.58 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501 12748  1314   0 10:18上午 ttys003    0:00.00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn [01;31m[Ktest-single.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;32m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ps -ef|grep test-single.py[26Dkill -9 8961 9766 10038 10575 10845                       10864 11134 11941 12478[?1l>
]2;kill -9 10864 11134 11941 12478]1;kill[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;32m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=kill -9 10864 11134 11941 12478[31Dps -ef|grep test-single.py     [?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501 12770   526   0 10:20上午 ??         2:01.98 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501 13040   526   0 10:21上午 ??         0:55.06 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501 13310   526   0 10:21上午 ??         0:30.80 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501 13580   526   0 10:21上午 ??         0:22.15 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501 13849  1314   0 10:22上午 ttys003    0:00.00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn [01;31m[Ktest-single.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;32m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ps -ef|grep test-single.py[26Dkill -9 10864 11134 11941 12478                   2770 13040 13310 13580[?1l>
]2;kill -9 12770 13040 13310 13580]1;kill[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;32m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=wwhich controller[?1l>
]2;which controller]1;whichcontroller not found
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;31m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=which controller[16Dkill -9 12770 13040 13310 13580[31Dps -ef|grep test-single.py     [?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501 13870   526   0 10:22上午 ??         1:53.46 python -u /Users/yangxw/learn_python/Mininet/mininet/[01;31m[Ktest-single.py[m[K
  501 14152  1314   0 10:24上午 ttys003    0:00.00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn [01;31m[Ktest-single.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;32m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=kkill -9 13780   870[?1l>
]2;kill -9 13870]1;kill[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;32m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ppwd[?1l>
]2;pwd]1;pwd/Users/yangxw/learn_python/Mininet/mininet/util
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;../mininet/util]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet/util[0m[27m[24m[J[01;32m➜  [36mutil[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccd ..[?1l>
]2;cd ..]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ninet/mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet/mininet[0m[27m[24m[J[01;32m➜  [36mmininet[00m [01;34mgit:([31mmaster[34m) [33m✗[00m [K[?1h=ccd ..[?1l>
]2;cd ..]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ython/Mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet[0m[27m[24m[J[01;32m➜  [36mMininet[00m [K[?1h=lls[?1l>
]2;ls -G]1;ls[1m[36mbin[39;49m[0m                  [1m[36mmininet[39;49m[0m              pip-selfcheck.json
[1m[36minclude[39;49m[0m              [1m[36mmininet-devel-mb[39;49m[0m
[1m[36mlib[39;49m[0m                  mininet-devel-mb.zip
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ython/Mininet]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet[0m[27m[24m[J[01;32m➜  [36mMininet[00m [K[?1h=ccd ..[?1l>
]2;cd ..]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;~/learn_python]7;file://yangxw-3.local/Users/yangxw/learn_python[0m[27m[24m[J[01;32m➜  [36mlearn_python[00m [K[?1h=lls[?1l>
]2;ls -G]1;ls52986a5340c64.ai         [1m[36mawesome-python3-webapp[39;49m[0m   [1m[36mpython_daemon_env[39;49m[0m
[1m[36mMininet[39;49m[0m                  [1m[36mmicroblog[39;49m[0m                [1m[36mpython_gunpg_env[39;49m[0m
README                   [1m[36mmorinus[39;49m[0m                  [1m[36mpython_script[39;49m[0m
[1m[36mShare[39;49m[0m                    preview.jpg              [1m[36mpython_stackoverflow_env[39;49m[0m
[1m[36mSkael[39;49m[0m                    [1m[36mpython-code-everyday[39;49m[0m     [1m[36mskyline[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;~/learn_python]7;file://yangxw-3.local/Users/yangxw/learn_python[0m[27m[24m[J[01;32m➜  [36mlearn_python[00m [K[?1h=ppython[?1l>
]2;python]1;pythonPython 2.7.10 (default, Oct 23 2015, 18:05:06) 
[GCC 4.2.1 Compatible Apple LLVM 7.0.0 (clang-700.0.59.5)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> exit)[K()
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;~/learn_python]7;file://yangxw-3.local/Users/yangxw/learn_python[0m[27m[24m[J[01;32m➜  [36mlearn_python[00m [K[?1h=vvirutalenv[?1l>
]2;virutalenv]1;virutalenvzsh: command not found: virutalenv
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;~/learn_python]7;file://yangxw-3.local/Users/yangxw/learn_python[0m[27m[24m[J[01;31m➜  [36mlearn_python[00m [K[?1h=vvirtualenv[?1l>
]2;virtualenv]1;virtualenvYou must provide a DEST_DIR
Usage: virtualenv [OPTIONS] DEST_DIR

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -v, --verbose         Increase verbosity.
  -q, --quiet           Decrease verbosity.
  -p PYTHON_EXE, --python=PYTHON_EXE
                        The Python interpreter to use, e.g.,
                        --python=python2.5 will use the python2.5 interpreter
                        to create the new environment.  The default is the
                        interpreter that virtualenv was installed with
                        (/usr/bin/python)
  --clear               Clear out the non-root install and start from scratch.
  --no-site-packages    DEPRECATED. Retained only for backward compatibility.
                        Not having access to global site-packages is now the
                        default behavior.
  --system-site-packages
                        Give the virtual environment access to the global
                        site-packages.
  --always-copy         Always copy files rather than symlinking.
  --unzip-setuptools    Unzip Setuptools when installing it.
  --relocatable         Make an EXISTING virtualenv environment relocatable.
                        This fixes up scripts and makes all .pth files
                        relative.
  --no-setuptools       Do not install setuptools in the new virtualenv.
  --no-pip              Do not install pip in the new virtualenv.
  --no-wheel            Do not install wheel in the new virtualenv.
  --extra-search-dir=DIR
                        Directory to look for setuptools/pip distributions in.
                        This option can be used multiple times.
  --download            Download preinstalled packages from PyPI.
  --no-download, --never-download
                        Do not download preinstalled packages from PyPI.
  --prompt=PROMPT       Provides an alternative prompt prefix for this
                        environment.
  --setuptools          DEPRECATED. Retained only for backward compatibility.
                        This option has no effect.
  --distribute          DEPRECATED. Retained only for backward compatibility.
                        This option has no effect.
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;~/learn_python]7;file://yangxw-3.local/Users/yangxw/learn_python[0m[27m[24m[J[01;31m➜  [36mlearn_python[00m [K[?1h=[?1l>
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;~/learn_python]7;file://yangxw-3.local/Users/yangxw/learn_python[0m[27m[24m[J[01;31m➜  [36mlearn_python[00m [K[?1h=vvirtua    v  wwhichh  h p    it ch python[?1l>
]2;which python]1;which/usr/bin/python
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;~/learn_python]7;file://yangxw-3.local/Users/yangxw/learn_python[0m[27m[24m[J[01;32m➜  [36mlearn_python[00m [K[?1h=vvirtualenv -p /usr/bin/py
[1;32mpydoc[0m*             [1;32mpython[0m*            [1;36mpython2.6-config[0m@  [1;32mpythonw[0m*         
[1;36mpydoc2.6[0m@          [1;32mpython-config[0m*     [1;36mpython2.7[0m@         [1;36mpythonw2.6[0m@      
[J[1;36mpydoc2.7[0m@          [J[1;36mpython2.6[0m@         [J[1;36mpython2.7-config[0m@  [J[1;36mpythonw2.7[0m@      [J[3A[0m[27m[24m[16Cvirtualenv -p /usr/bin/py[Kthon Mininet2.7[?1l>
[J]2;virtualenv -p /usr/bin/python Mininet2.7]1;virtualenvRunning virtualenv with interpreter /usr/bin/python2.7
New python executable in /Users/yangxw/learn_python/Mininet2.7/bin/python
Installing setuptools, pip, wheel...done.
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;~/learn_python]7;file://yangxw-3.local/Users/yangxw/learn_python[0m[27m[24m[J[01;32m➜  [36mlearn_python[00m [K[?1h=lls[?1l>
]2;ls -G]1;ls52986a5340c64.ai         [1m[36mawesome-python3-webapp[39;49m[0m   [1m[36mpython_gunpg_env[39;49m[0m
[1m[36mMininet[39;49m[0m                  [1m[36mmicroblog[39;49m[0m                [1m[36mpython_script[39;49m[0m
[1m[36mMininet2.7[39;49m[0m               [1m[36mmorinus[39;49m[0m                  [1m[36mpython_stackoverflow_env[39;49m[0m
README                   preview.jpg              [1m[36mskyline[39;49m[0m
[1m[36mShare[39;49m[0m                    [1m[36mpython-code-everyday[39;49m[0m
[1m[36mSkael[39;49m[0m                    [1m[36mpython_daemon_env[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;~/learn_python]7;file://yangxw-3.local/Users/yangxw/learn_python[0m[27m[24m[J[01;32m➜  [36mlearn_python[00m [K[?1h=p ccd mi
[J[1;31mMininet[0m/     [J[1;31mMininet2.7[0m/  [J[1;31mmicroblog[0m/ [J[A[0m[27m[24m[16Ccd mi[Kni
[J[A[23CM[3Cnet2.7[1m/[0m[0m [?1l>
[J]2;cd Mininet2.7]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..on/Mininet2.7]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7[0m[27m[24m[J[01;32m➜  [36mMininet2.7[00m [K[?1h=ppwd[?1l>
]2;pwd]1;pwd/Users/yangxw/learn_python/Mininet2.7
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..on/Mininet2.7]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7[0m[27m[24m[J[01;32m➜  [36mMininet2.7[00m [K[?1h=lls[?1l>
]2;ls -G]1;ls[1m[36mbin[39;49m[0m                [1m[36minclude[39;49m[0m            [1m[36mlib[39;49m[0m                pip-selfcheck.json
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..on/Mininet2.7]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7[0m[27m[24m[J[01;32m➜  [36mMininet2.7[00m [K[?1h=ccd bin[?1l>
]2;cd bin]1;cd[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J[01;32m➜  [36mbin[00m [K[?1h=ssource ac
[1;32mac[0m*               [1;36maclocal[0m@          activate.csh                      
[1;36maccept[0m@           [1;36maclocal-1.15[0m@     activate.fish                     
[J[1;32maccton[0m*           [Jactivate          [Jactivate_this.py  [J                [3A[0m[27m[24m[7Csource ac[Kc tib
[J[A[19C vate[?1l>
[J]2;source activate]1;source[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=lls[?1l>
]2;ls -G]1;lsactivate         [31measy_install[39;49m[0m     [31mpip2.7[39;49m[0m           [35mpython2.7[39;49m[0m
activate.csh     [31measy_install-2.7[39;49m[0m [31mpython[39;49m[0m           [31mwheel[39;49m[0m
activate.fish    [31mpip[39;49m[0m              [31mpython-config[39;49m[0m
activate_this.py [31mpip2[39;49m[0m             [35mpython2[39;49m[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=ppip intsll  all select[?1l>
]2;pip intsall select]1;pipERROR: unknown command "intsall" - maybe you meant "install"
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;31m➜  [36mbin[00m [K[?1h=ppip install select[?1l>
]2;pip install select]1;pipCollecting select
[31m  Could not find a version that satisfies the requirement select (from versions: )[0m
[31mNo matching distribution found for select[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;31m➜  [36mbin[00m [K[?1h=ppip install pt ython -e select[?1l>
]2;pip install python-select]1;pipCollecting python-select
[31m  Could not find a version that satisfies the requirement python-select (from versions: )[0m
[31mNo matching distribution found for python-select[0m
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;31m➜  [36mbin[00m [K[?1h=ppython[?1l>
]2;python]1;pythonPython 2.7.10 (default, Oct 23 2015, 18:05:06) 
[GCC 4.2.1 Compatible Apple LLVM 7.0.0 (clang-700.0.59.5)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> i[Kisinstance()')')h')1')',)b)a)s)e)s)t)r)i)n)g)
True
>>> exit()
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=pprp  pps -ef|grep toop  po-mb*[?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} topo-mb*]1;pszsh: no matches found: topo-mb*
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;31m➜  [36mbin[00m [K[?1h=ps -ef|grep topo-mb* -tree2.py[?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501 31715  1314   0 11:30上午 ttys003    0:00.00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn [01;31m[Ktopo-mb-tree2.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=ps -ef|grep topo-mb-tree2.py[?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501 33949   526   0  2:25下午 ??         0:15.43 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 34217   526   0  2:25下午 ??         0:03.35 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 34486  1314   0  2:25下午 ttys003    0:00.00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn [01;31m[Ktopo-mb-tree2.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=kkill -9 33949 34217[?1l>
]2;kill -9 33949 34217]1;kill[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=kill -9 33949 34217[19Dps -ef|grep topo-mb-tree2.py[?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501 34501  1314   0  2:25下午 ttys003    0:00.00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn [01;31m[Ktopo-mb-tree2.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=ps -ef|grep topo-mb-tree2.py[?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501 34507   526   0  2:25下午 ??         3:42.73 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 34782   526   0  2:27下午 ??         1:52.24 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 35071  1314   0  2:29下午 ttys003    0:00.00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn [01;31m[Ktopo-mb-tree2.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=kkill -9 34507 34782[?1l>
]2;kill -9 34507 34782]1;kill[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=kill -9 34507 34782[19Dps -ef|grep topo-mb-tree2.py[?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501 35086   526   0  2:30下午 ??         1:24.90 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 35355   526   0  2:31下午 ??         0:35.74 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 35625   526   0  2:31下午 ??         0:12.88 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 35894  1314   0  2:31下午 ttys003    0:00.00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn [01;31m[Ktopo-mb-tree2.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=kkill -9 35086 35355 35625[?1l>
]2;kill -9 35086 35355 35625]1;kill[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=kill -9 35086 35355 35625[25Dps -ef|grep topo-mb-tree2.py[?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501 35925   526   0  2:32下午 ??         3:29.62 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 36196   526   0  2:33下午 ??         3:06.66 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 36468   526   0  2:35下午 ??         1:24.72 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 36743  1314   0  2:36下午 ttys003    0:00.00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn [01;31m[Ktopo-mb-tree2.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=kkill -9 35925 36196 36468[?1l>
]2;kill -9 35925 36196 36468]1;kill[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=kill -9 35925 36196 36468[25Dps -ef|grep topo-mb-tree2.py[?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501 36757   526   0  2:37下午 ??         3:17.34 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 37027   526   0  2:37下午 ??         2:46.38 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 37566   526   0  2:39下午 ??         1:10.76 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 37837  1314   0  2:40下午 ttys003    0:00.00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn [01;31m[Ktopo-mb-tree2.py[m[K
[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=kkill -9 36757 37027 37566[?1l>
]2;kill -9 36757 37027 37566]1;kill[1m[7m%[27m[1m[0m                                                                                ]2;yangxw@yangxw-3]1;..ininet2.7/bin]7;file://yangxw-3.local/Users/yangxw/learn_python/Mininet2.7/bin[0m[27m[24m[J(Mininet2.7) [01;32m➜  [36mbin[00m [K[?1h=kill -9 36757 37027 37566[25Dps -ef|grep topo-mb-tree2.py[?1l>
]2;ps -ef | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn} ]1;ps  501 37850   526   0  2:41下午 ??         1:22.69 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 38123   526   0  2:41下午 ??         1:05.07 python -u /Users/yangxw/learn_python/Mininet/mininet-devel-mb/[01;31m[Ktopo-mb-tree2.py[m[K
  501 38394   5