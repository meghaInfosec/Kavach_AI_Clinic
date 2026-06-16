Indicator_Type,Indicator_Value,Category,Confidence,Packet_Range_Frames,Time_Range_Seconds,Supporting_Filter,Related_Hypothesis,Notes
IP,C2 Server,37.228.70.134,C2,High,791-26451,0-4809,ip.addr==37.228.70.134,Hypothesis 1 (Beaconing),Consistent ~202s beaconing interval, no SNI
IP,C2 Server,192.236.155.230,C2 + Exfil,High,1200-24500,150-4600,ip.addr==192.236.155.230,Hypothesis 1,Primary exfiltration destination (7MB+)
IP,Lateral Movement,10.5.26.4,Internal Lateral,High,4500-8000,300-900,ip.addr==10.5.26.4 && ip.addr==10.5.26.132,Hypothesis 2 (Lateral),svcctl / PsExec style lateral movement to DC
URI Pattern,Exfiltration,/collect/.*,Data Exfil,Medium,1450-3200,180-450,http.request.uri matches "/collect/",Hypothesis 3,Trickbot host data POST with fingerprint
User-Agent,Malware UA,"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",C2,Medium,800-26000,50-4750,http.user_agent contains "Mozilla/5.0",Hypothesis 1,Common Cobalt Strike / Trickbot UA
Port,Beacon Port,80,C2,High,Multiple long sessions,100-4800,tcp.port==80 && ip.addr==5.199.162.3,Hypothesis 1,Long-lived low-data sessions typical of CS beacons
DNS Query,Suspicious DNS,*,Recon,Low,300-600,20-80,dns.qry.name contains "victorypunk",Hypothesis 2,Internal domain resolution during lateral movement
