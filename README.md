# Simple-Router
SDN assignment
#Simple Router

我目前实现了对ARP request 和ICMP request 的解析和回复，实现了从client ping router。项目上传到了https://github.com/fengziyue/Simple-Router

## 一，配置环境。

首先将源切换到阿里云镜像：

打开：`/etc/apt/sources.list`

替换默认的`http://archive.ubuntu.com/`为`mirrors.aliyun.com`

然后安装必要的包：

```bash
sudo apt-get update
sudo apt-get install -y git vim-nox python-setuptools python-all-dev flex bison traceroute
```

因为我使用的是moodle上下载的虚拟机，所以已经有了POX和Mininet

安装 ltprotocol：

```
cd ~
git clone git://github.com/dound/ltprotocol.git
cd ltprotocol 
sudo python setup.py install
```

在POX中切换到特定版本：

`cd ~/pox`

`git checkout f95dd1a81584d716823bbf565fa68254416af603`

接下来按照官方教程中的步骤操作即可

## 二，填充路由器代码

完成后的sr_router.c 如下：

```c
/**********************************************************************
* file:  sr_router.c
* date:  Mon Feb 18 12:50:42 PST 2002
* Contact: casado@stanford.edu
*
* Description:
*
* This file contains all the functions that interact directly
* with the routing table, as well as the main entry method
* for routing.
*
**********************************************************************/

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

/*---------------------------------------------------------------------
* Method: sr_init(void)
* Scope:  Global
*
* Initialize the routing subsystem
*
*---------------------------------------------------------------------*/

void send_arp_reply(struct sr_instance* sr,
	uint8_t * packet/* lent */,
	unsigned int len,
	char* interface/* lent */)
{

	uint8_t buf[len];
	int i;
	
	for (i = 0; i<len; i++)
		buf[i] = packet[i];
	for (i = 0; i<6; i++)
		buf[i] = packet[i + 6];
	struct sr_if *a = sr->if_list;

	if (packet[38] == 10) {
		for (i = 0; i<6; i++) {
			buf[i + 6] = a->addr[i];
		}
	}
	else if (packet[38] == 172) {
		a = a->next;
		for (i = 0; i<6; i++) {
			buf[i + 6] = a->addr[i];
		}
	}
	else if (packet[38] == 192) {
		a = a->next->next;
		for (i = 0; i<6; i++) {
			buf[i + 6] = a->addr[i];
		}
	}

	buf[21]++;
	for (i = 0; i<6; i++) {
		buf[22 + i] = buf[6 + i];
		buf[32 + i] = buf[i];
	}
	for (i = 0; i<4; i++) {
		buf[28 + i] = packet[38 + i];
		buf[38 + i] = packet[28 + i];
	}


	printf("%d",sr_send_packet(sr, buf, len, interface));
}



void send_icmp_reply(struct sr_instance* sr,
	uint8_t * packet/* lent */,
	unsigned int len,
	char* interface/* lent */)
{
	uint8_t buf[len];
	int i;
	
	for (i = 0; i<len; i++)
		buf[i] = packet[i];
	for (i = 0; i<6; i++)
		buf[i] = packet[i + 6];
	struct sr_if *a = sr->if_list;

	if (packet[30] == 10) {
		for (i = 0; i<6; i++) {
			buf[i + 6] = a->addr[i];
		}
	}
	else if (packet[30] == 172) {
		a = a->next;
		for (i = 0; i<6; i++) {
			buf[i + 6] = a->addr[i];
		}
	}
	else if (packet[30] == 192) {
		a = a->next->next;
		for (i = 0; i<6; i++) {
			buf[i + 6] = a->addr[i];
		}
	}

	
	
	for (i = 0; i<4; i++) {
		buf[26 + i] = packet[30 + i];
		buf[30 + i] = packet[26 + i];
	}
	buf[34]=0;

/*ICMP checksum*/
	buf[36]=0;
	buf[37]=0;
	int cks_icmp=cksum(&buf[34],len-34);
	buf[37]=cks_icmp/256;
	buf[36]=cks_icmp%256;




/*IP checksum*/
	buf[24]=0;
	buf[25]=0;
	int cks_ip=cksum(&buf[14],20);
	buf[25]=cks_ip/256;
	buf[24]=cks_ip%256;

	printf("%d",sr_send_packet(sr, buf, len, interface));
}



void sr_init(struct sr_instance* sr)
{
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/* Add initialization code here! */

} /* -- sr_init -- */

  /*---------------------------------------------------------------------
  * Method: sr_handlepacket(uint8_t* p,char* interface)
  * Scope:  Global
  *
  * This method is called each time the router receives a packet on the
  * interface.  The packet buffer, the packet length and the receiving
  * interface are passed in as parameters. The packet is complete with
  * ethernet headers.
  *
  * Note: Both the packet buffer and the character's memory are handled
  * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
  * packet instead if you intend to keep it around beyond the scope of
  * the method call.
  *
  *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
	uint8_t * packet/* lent */,
	unsigned int len,
	char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n", len);

	/* fill in code here */	

if(packet[13] == 6) 
	send_arp_reply(sr,packet,len,interface);
if(packet[13] == 0)
	send_icmp_reply(sr,packet,len,interface);



}/* end sr_ForwardPacket */


```



## 三，运行

这个实验是在Mininet 中定义一个如下的网络拓扑，然后使用POX充当控制器，而POX将Router收到的所有包发给rc来解析并处理。rc由我们的sr_router.c程序编译得到。这样就在SDN上虚拟出了一个传统的路由器。

![Capture](https://github.com/fengziyue/Simple-Router/blob/master/sr/Capture.PNG)

所以，我们我们先用`run_pox.sh`运行POX，然后用`run_mininet.sh`创建虚拟网络。最后使用编译出的rc程序充当路由器。

实际ping 效果如下：

![Capture1](https://github.com/fengziyue/Simple-Router/blob/master/sr/Capture1.PNG)

![Capture2](https://github.com/fengziyue/Simple-Router/blob/master/sr/Capture2.PNG)

rc程序输出如下：

![Capture3](https://github.com/fengziyue/Simple-Router/blob/master/sr/Capture3.PNG)

图中，第一个长度为42的包是ARP request 包，后面的长度为98的包为ICMP request 包。

使用wireshark抓包分析如下：

![Capture4](https://github.com/fengziyue/Simple-Router/blob/master/sr/Capture4.PNG)

可以看到ARP request，reply 和 ICMP request, reply。

## 四，总结

通过这次实验，我再次加深了对网络的理解。从以太网层到IP层，ICMP层，完全手动进行分析帧格式，填充帧内容，计算校验和等工作。我对网络层次模型和帧封装的细节有了更清晰的认识。也在很多小细节上卡了一段时间。比如校验和填充的时候小端和大端的差异，计算校验和的顺序和范围。这也体现了理论学习如果不结合实际实验，必然会留下很多知识的死角。
