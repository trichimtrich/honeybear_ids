## HoneyBear Framework
We are developing HoneyBear framework, which is a combination of honeypot and IDS, also has modularity in design. Packet flows are monitored from routing step in router to detector modules which perform behavior analysis on each stream of packets. Results of analytical process are then used for directing packet flows to appropriate path. 

Below is the structure of HoneyBear framework:
<p align="center"><img src="/infrastructure.png"></p>

HoneyBear framework will include:
- Hidden level: 
	- Packet Sniffer: intercept and log packets that passes over router. We will try to collect all packet information in here.
	- Detector: is heart of the system, this is not a usual detector which perform detective process, instead, it is a combination of sub detectors modules, which have been already developed or can be designed by users. Main function of detector is not only to manage, collect analysis results from sub detectors but also to control packet flows into each sub detector.
	- Redirector: After having analysis results, this part has responsibility for direct packet flows in internal network. Now, network structure has 2 nodes: Fake and Real.
	- Logger: log outgoing analyzed packets for further study.
- Interact level:
	- Web GUI: user interface used for displays relevant information including alerts, log, etc.
	- Configuration: configure parameters, priorities, manage sub detector modules, etc.

<p align="center"><img src="/flow.png"></p>

## Packet Label
Incoming packets are logged by Packet Sniffer, then analyzed by sub detectors modules in Detector. After that, packets would be labelled as one of these three states:
- (a) Normal
- (b) Critical
- (c) Unknown

With each state, framework will record and mark packets based on their IP address, Source Port and Destination Port. Redirector then directs packet flows to suitable path in internal network. There are 2 nodes right now, so this is what will happen:
- Normal packets will be directed to Real node
- Unknown and critical packets will be directed to Fake node. Here, they will be analyzed by behavior monitoring, which identify attack signatures. These signatures are used by sub detectors later.

## Sub Detector Modules
HoneyBear framework has modularity in design, which means each part of HoneyBear will work separately as a module, but they have a unified management. Detector is the heart of the system. As mentioned above, function of detector is not only to manage, collect analysis results from sub detectors but also to control packet flows into each sub detector. 
Each sub detector module will have packet input, separated database and signatures. Each of them will be responsible for a different type of attacks. For example:
- SQL Injection Detector module.
- DDoS Detector module.
- Shellcode Detector module.
Thus, they should be independently developed and will be integrated to framework when they are ready.
## Machine Learning in Sub Detector Module
