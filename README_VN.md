## HoneyBear Framework:
Chúng tôi phát triển mô hình Framework HoneyBear là một honeypot / IDS tích hợp được cấu thành dưới dạng module hoá. Nó nắm giữ toàn bộ flow của packet trong quá trình routing (trong router) cũng như được đánh giá qua bộ detector module để nghiên cứu hành vi và directing vào internal network theo lộ trình thích hợp.

Mô hình Honeybear hoạt động trên cấu trúc mạng như sau:
<p align="center"><img src="/infrastructure.png"></p>

Bộ Framework gồm các thành phần chính:
- Hidden level: quá trình hoạt động ngầm
	- Packet Sniffer: Bắt các gói tin khi nó được gửi đến router để routing. Tại đây ta sẽ tiến hành thu thập toàn bộ thông tin của gói tin.
	- Detector: Là trái tim của toàn bộ hệ thống, đây không phải là một detector thông thường (có các chức năng) mà nhiệm vụ của nó là tổng hợp các sub detector module (do người dùng, hoặc một số đã phát triển sẵn) và phân phối packet cho các sub module ấy để thu nhận kết quả đánh giá.
	- Redirector: Sau khi thu nhận kết quả đánh giá, thành phần này sẽ chuyển hưởng packet theo lộ trình trong internal network. Hiện tại trên cấu trúc mạng có 2 node là Fake và Real.
	- Logger: Thu nhận các out-going packet của các traffic đã được đánh giá để làm analysis cần thiết hoặc chỉ là ghi log lại.
- Interact level: tương tác với user
	- Web GUI: hiển thị các thông tin, alert, log, ...
	- Configurator: cấu hình các thông số, priority, set module detector, ...

<p align="center"><img src="/flow.png"></p>

## Packet Label:
Như ở phần trên, packet đi vào sẽ bị thu thập hết bởi Packet Sniffer và đánh giá bằng Detector. Sau quá trình đánh giá, nó sẽ được mark cho 1 nhãn gồm có 1 trong 3 trạng thái:
- (a) Normal
- (b) Critical
- (c) Unknown

Với mỗi trạng thái đó, framework sẽ tiến hành ghi nhận và đánh dấu lại traffic (dựa trên ip, port của src và dest để đánh dấu các packet tiếp theo) và bộ Redirector sẽ điều hướng gói packet hiện tại vào luồng internal network hợp lí. Hiện tại có 2 máy thì với mỗi loại cụ thể sẽ như sau:
- (a): Packet follow bình thường, không thay đổi hướng đi của nó vào Real Target
- (b): Điều hướng vào máy Fake Target
- (c): Đây là nhãn đặc biệt vì detector phân vân giữa quyết định nó có độc hại hay không, chúng ta sẽ điều hướng nó vào máy Fake Target và tiếp tục nghiên cứu các hành động khi có packet đó đi vào có tác động gì đến hệ thống (bằng các kĩ thuật Monitor trong Malware Analysis,...) để đánh giá tính độc hại của nó, và trong output traffic framework sẽ gather các thông tin đó và bổ sung vào detector.

## Detector module:
HoneyBear Framework được phát triển dưới dạng module base, tức là các thành phần của nó sẽ như một Module và được Bear kết hợp lại một khối (theo một cấu hình cụ thể). Detector là nhân tố trung tâm của hệ thống đấy, nó là phần chính quản lí tất cả các thành phần sub Detector (đã phát triển sẵn hoặc do người dùng tích hợp thêm vào), nhiệm vụ của nó là phân phối packet cho từng sub Detector và sau quá trình thu nhận các kết quả được đánh giá, nó sẽ đánh giá cuối cùng packet đó và gán nhãn (như ở trên) cho traffic. Cách thức hoạt động khá giống với IDS.

Mỗi Module trong Detector sẽ có đầu vào là 1 gói packet, chúng có các cơ sỡ dữ liệu, nhưng signature riêng biệt để tự mình đánh giá một mảng nào đó của Packet. Ví dụ:
- Sql Injection Detector
- DDoS Detector
- Shellcode Detector
- ...

> Machine Learning in Detector Module?

Như vậy các module này được phát triển độc lập và sẽ được gắn vào framework khi chúng sẵn sàng
