Threat ID	Asset	Attack Summary	MITRE Tactic
TR01	EC2	"Unauthorized access

Attacker may try to exploit the vulnerabilities in EC2, brute-force attack or introduce malicious exploits in EC2.

Operating systems on the EC2 can be accessed via different ways (e.g. SSH, RDP, HTTP) and unauthorized access can be performed via stolen credentials, OS, and web vulnerabilities (e.g. SSRF). An attacker can access EC2 OS and change specific parameters on it, install backdoors, escalate their privileges or exfiltrate sensitive data."	"TA0001: Initial Access
TA0004: Privilege Escalation"
TR02	EC2	"Denial of service

Malicious user may launch a Denial of service activities on EC2 resulting the instance to be unavailable for service."	TA0040: Impact
TR03	EC2	"Denial of service

Malicious user may stop EC2 resulting the service to be unavailable for service."	TA0040: Impact
TR04	EC2	"Denial of service

Malicious user may stop system service running on EC2 resulting the service to be unavailable for service (systemctl, systemd)."	TA0040: Impact
TR05	EC2	"Privilege Escalation

Malicious user gain administrator/root privilege to EC2 may perform unauthorized activities.

Privilege Escalation by unauthorized rogue instances

Instances can be started in unauthorized subnets and VPC with unauthorized parameters (e.g. Security Group). Particular instances can have significant costs. Instances can be created by using sensitive or malicious AMIs. An attacker can launch unauthorized instances to escalate the privileges in order to access other resources or use them for crypto mining, or run instances from sensitive AMI and access data on it.

Privilege Escalation by instance modification

Instance attributes can be modified: disableApiTermination, instanceInitiatedShutdownBehavior, rootDeviceName, blockDeviceMapping, productCodes, sourceDestCheck, groupSet, ebsOptimized, SriovNetSupport, enaSupport, enclaveOptions. An attacker can change those attributes and impact the integrity and availability of instance, make it accessible from the Internet or allow an attacker to intercept traffic in the network or forge packets with different source addresses. Additionally, an attacker can modify instance type, UserData, kernel, ram disk by stopping the instance and get the ability to execute code on it, exfiltrate data from it or initiate denial of wallet attacks by using the most expensive instances."	"TA0001: Initial Access
TA0004: Privilege Escalation:"
TR06	EC2, Security Group,	"Security Group Changes

An attacker may modify the Security group with intention to allow access to EC2 instance from outside of VPC."	"TA0010: Data Exfiltration

TA0005: Defense Evasion"
TR07	EC2	"Network Information and Lateral movement.

An attacker conducts recon activities (e.g. network discovery) on the EC2 network using Port Scanner tool, Reachability Analyzer or Network Access Analyzer. Lateral movement from compromised EC2 instance to other AWS services"	"TA0043: Reconnaissance - Gather Victim Network Information

TA0008: Lateral Movement"
TR08	EC2	"Unauthorized access to EC2 Instance Metadata Service (IMDS)

An Attacker would like to use a weakness in the application (e.g. Server Side Request Forgery, XML External Entity Injection, Remote Code Execution) to get access to the EC2 IMDS so that I can get temporary security credentials."	TA0009: Collection
TR09	EC2	"Man-in-the-middle attacks

As an Attacker would like to sniff and hijack sessions between EC2 instances and/or other AWS services and/or clients."	"TA0009: Collection

Adversary-in-the-Middle"
TR10	EC2	"Data Exfiltration

Malicious user may exfiltrate data from compromised compute targets."	"TA0010: Data Exfiltration: 

Exfiltration - exfiltration over other network medium"
TR11	EC2, AMI	"Deploy a new EC2 instance with a compromised/outdated AMI

An Attacker can start a new EC2 instance that has control over in a protected environment.

Instances can be stopped for future use. Some of them can be stopped for a very long time and multiple remote exploits can be available on the date. An attacker can start an outdated instance, run an exploit against it and gather sensitive data, escalate privileges by using attached roles or in the network, collect credentials with misconfigured rotation parameters."	"TA0002: Execution

Command and Scripting Interpreter

TA0004: Privilege Escalation

Launch another attack"
TR12	EC2, EBS	"Data exfiltration via copying AMI, EBS snapshots or volumes

An Attacker can exfiltrate data by copying AMI, EBS snapshots or volumes."	"TA0010: Data Exfiltration: 

Exfiltration - exfiltration over other network medium"
TR13	EC2, EBS	"Ransomware Attack

An attacker with compromised credentials may copy an unauthorized software (like ransomware) for encrypting the data in EC2, EBS volumes to cause service disruption."	TA0002: Execution
TR14	EBS	"EBS with no encryption

An user may create the EBS without enabling data at rest encryption using CMK. Creating File System without data at encryption may lead to data leakage and/or non-compliance with ICS policy.

Volume encryption should be enabled by default in all regions. An attacker can disable volume encryption by default or specify unauthorized default KMS key which potentially can escalate privileges for AWS insiders."	"TA0010: Data Exfiltration: 

TA0002: Execution

Launch another attack"
TR15	EC2, EIP	"Enable Public Access by adding EIP

An Attacker may assign the Elastic IP to the EC2 to get connectivity from public networks."	TA0010: Data Exfiltration
TR16	EC2	"Disable Logging

An attacker can disable the logging of events/activities carried out on Amazon EC2 to hide the user actions."	TA0005: Defense Evasion
TR17	EC2	"Disable security agents: Tanium. Qualys, DCS, CloudWatch Agents

An attacker can disable security agents that are baked in during AMI preparation process."	TA0005: Defense Evasion
TR18	EC2	"Denial of Service

EC2 instances, volumes, and fleets can be deleted via an API Call. An attacker can impact a critical entity to affect any apps using EC2 or affect the data itself."	"TA0040: Impact

Disruption of Service"
TR19	EC2	"Unauthorized data access from AWS insider

Sensitive data can be stored on the instance storage, on the EBS volumes and snapshots. An attacker (AWS insider) can access data on unencrypted volumes/snapshots and exfiltrate or manipulate it."	"TA0040: Impact

Data manipulation"
TR20	EC2	"Privilege escalation and Denial of Service by IMDS modification

Instance metadata can be enabled and parameters like metadata hops, version, tags can be altered. An attacker can escalate their privileges by enabling instance metadata, downgrading it to version 1, increasing the number of hops it can travel, adding tags to response requests, disable instance metadata and affect operations on the instance."	"TA0002: Execution

Launch another attack"
TR21	EC2	"=HYPERLINK(""http://169.254.169.254/latest/meta-data/"",""Discovery attack by viewing instance metadata

Instance metadata can be retrieved from """"http://169.254.169.254/latest/meta-data/"""" or """"http://[fd00:ec2::254]/latest/meta-data/"""" and can contain important and sensitive information. An attacker can retrieve instance metadata and use it for further attacks.

Particular EC2 configurations can contain important information such as private ip addresses, parameters, security rules, configurations, and instance role credential. An attacker can reveal this information and use it for further attacks."")"	"TA0002: Execution

Launch another attack"
TR22	EC2	"Denial of Service slightly affecting availability

Capacity Reservations can be canceled, instance maintenance options modified, instance event notification deregistered, fast snapshots restores disabled. An attacker can use those APIs to cause DoS on those non important functions."	"TA0040: Impact

Disruption of Service"
TR23	EC2	"Privilege escalation and defense evasion by volume modification

Multiattach and other performance parameters for volumes can be modified. An attacker can modify those volume parameters and escalate privileges with the ability to attach volume to another instance or affect volume (and instance) capabilities which can result in loss of data (e.g. logs)."	"TA0002: Execution

Launch another attack"
TR24	EC2	"Unauthorized data access by restoring volume from unauthorized snapshot

The root volume can either be restored to its initial launch state, or it can be restored using a specific snapshot. An attacker can restore root volume from unauthorized sensitive or malicious snapshot and exfiltrate/manipulate data in the first case or use it for further attacks in the second. An attacker can cause DoS by restoring root volume to initial state or by using corrupted snapshot."	"TA0040: Impact: 

Data manipulation"
TR25	EC2	"Unauthorized data access by attaching sensitive volume to unauthorized instance

EBS volumes can contain sensitive information and can be malicious as well. Sensitive information can be moved from authorized volumes to unauthorized. An attacker can exfiltrate or manipulate data by attaching volume with sensitive information to unauthorized instance or attach unauthorized volume and use it as an exfiltration step by writing sensitive information on it."	"TA0040: Impact 

Data manipulation"
TR26	EC2	"Denial of wallet via volume creation

Some volumes have significant costs (especially io). An attacker can create or import enormous amounts of volumes and cause denial of wallet."	"TA0040: Impact 

Disruption of Service"
TR27	EC2	"Data exfiltration by sharing snapshot

Snapshots can be shared with specific accounts or made public. An attacker can exfiltrate data by sharing a snapshot with an unauthorized account or making it public."	"TA0010: Exfiltration

Data theft"
TR28	EC2	"Denial of Service critically affecting data, resources integrity and availability via snapshot deletion or modification

EC2 snapshots can be deleted or modified via an API Call. An attacker can impact critical snapshot to affect any apps using EC2 or affect the data itself."	"TA0040: Impact

Disruption of Service"
TR29	EC2	"Unauthorized access or compliance issue by changing KMS key for snapshot

Snapshots can be copied in the same or another region with different KMS keys. An attacker can copy a snapshot to an unauthorized region or with an unauthorized customer managed KMS key that they control."	"TA0040: Impact

Disruption of Service

Launch another attack"
TR30	EC2, S3	"Data exfiltration by storing/exporting image on cross-account S3 bucket

Images can be stored/exported on/to S3 buckets (including cross-account). An attacker can store an image in an unauthorized or public location and access the image from it."	"TA0010: Exfiltration

Data theft"
TR31	EC2, ASG	"Delete Auto Scaling group

Attacker may delete the ASG to cause DoS and potential application failure."	"TA0040: Impact

Disruption of Service"
TR32	EC2, ASG	"Modify Auto Scaling group setting(s)

By modifying the ASG settings attacker can cause DoS and potential application failure.

Group size - Specify the size of the Auto Scaling group by changing the desired capacity. Attacker can reduce the group size cause application to be overloaded due to lack of resources.
Launch configuration / Launch template - attacker can modify the use of LC or LT that don't meet application requirements and can cause application to be overloaded due to lack of resources or use improper configuration.
Network - attacker can modify VPC and AZ settings that can cause outage by limiting HA and resiliency.
Load balancing - attacker can disable LB (*if used) that can cause traffic to be not balanced and overload application.
Health checks - attacker can modify/disable health checks for ELB (*if used) and modify/extend grace period that can cause longer expected startup period of your application
Termination policies - can cause interruption during scale-in"	"TA0040: Impact

Disruption of Service

TA0002: Execution

Launch another attack"
TR33	EC2, ASG	"Delete Predictive/Dynamic scaling policies

By deleting scaling policies attacker can impact adding more instances (referred to as scaling out) to deal with high demand at peak times, and run fewer instances (referred to as scaling in) to reduce costs during periods of low utilization that can cause DoS."	"TA0040: Impact

Disruption of Service"
TR34	EC2, ASG	"Modify Predictive/Dynamic scaling policies

By modifying scaling policies attacker can impact adding more instances (referred to as scaling out) to deal with high demand at peak times, and run fewer instances (referred to as scaling in) to reduce costs during periods of low utilization that can cause DoS."	"TA0040: Impact

Disruption of Service"
TR35	EC2, ASG	"Delete/Modify Scheduled actions

By modifying/deleting scheduled policies attacker can impact adding more instances (referred to as scaling out) to deal with high demand at peak times, and run fewer instances (referred to as scaling in) to reduce costs during periods of low utilization that can cause DoS."	"TA0040: Impact

Disruption of Service"
TR36	EC2, ASG	"Modify Instance Management: Detach/Standby instance

By modifying Instance Management attacker can impact instances in the group that can cause DoS."	"TA0040: Impact

Disruption of Service"
TR37	EC2, ASG	"Modify Lifecycle hooks

By modifying Lifecycle hooks attacker can impact instances in launch or before they terminate that can cause DoS."	"TA0040: Impact

Disruption of Service"
TR38	EC2, ASG	"Modifying/Deleting SNS topics whenever Amazon EC2 Auto Scaling

By modifying/Deleting SNS topic attacker can disable notifications triggered by ASG."	"TA0040: Impact

Disruption of Service"

