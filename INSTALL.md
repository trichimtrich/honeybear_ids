## Independences
### Core
- [libnfnetlink](http://www.netfilter.org/projects/libnfnetlink/downloads.html)
- [libmnl](http://www.netfilter.org/projects/libmnl/downloads.html)
- [libnetfilter_queue](http://www.netfilter.org/projects/libnetfilter_queue/downloads.html)

`apt-get install libnetfilter-queue-dev`

### WebUI
`pip install flask`

## Compile
### Core
`gcc -lnetfilter_queue -ldl -o bear bear.c`

### Module
`gcc -shared -fPIC detectX.c -o detectX.so`

## Configuration
Add new detect module in bear.conf
```
[module]
name=Module X
file=./modules/detectX.so
```

## Run
### Core
open queue number 0
`iptables -A INPUT -j NFQUEUE --queue-num 0`

run core
`sudo ./bear`

<p align="center"><img src="/screenshot1.png"></p>

### WebUI
`sudo python run.py`

<p align="center"><img src="/screenshot2.png"></p>
