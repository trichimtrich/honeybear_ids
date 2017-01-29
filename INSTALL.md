## Independences
### Core
- libnfnetlink
- libmnl
- libnetfilter_queue
- apt-get install libnetfilter-queue-dev

### WebUI
- pip install flask

## Compile
### Core
gcc -lnetfilter_queue -ldl -o bear bear.c 

### Module
gcc -shared -fPIC detectX.c -o detectX.so

## Configuration
Add new detect module in bear.conf
> [module]
> name=Module X
> file=./modules/detectX.so

## Run
### Core
iptables -A INPUT -j NFQUEUE --queue-num 0
sudo ./bear

### WebUI
sudo python run.py