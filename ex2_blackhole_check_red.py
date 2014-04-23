#place this script under ~/pyretic/pyretic/examples
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.examples.ex2_dumb_forwarding import dumb_forwarder

class BlackholeCheckerRedirector(DynamicPolicy):
    def __init__(self, threshold_rate, blackhole_port_dict, IPs_and_TCP_ports_to_protect):
        '''
        threshold_rate = 3 #packets per sec (you can tune it if needed)
        blackhole_port_dict = {'untrusted' : 2, 'trusted' : 1, 'blackhole' : 3} #see exercise setup (figure 2)
        ips_and_tcp_ports_to_protect = [("10.1.1.6",22),("10.1.1.7",80)] #protect ssh and apache servers
        '''
        super(BlackholeCheckerRedirector, self).__init__()
        self.threshold_rate = threshold_rate
        self.port_dict = blackhole_port_dict
        self.ips_tcp_ports = IPs_and_TCP_ports_to_protect
        self.untrusted_incoming_traffic_to_check = union([match(inport=self.port_dict['untrusted'], dstip=i, protocol=6, dstport=p) for (i,p) in self.ips_tcp_ports])       
        self.forward = dumb_forwarder(self.port_dict['trusted'],self.port_dict['untrusted']) #initial forwarding scheme 
        #ATTENTION: other useful attributes???
        self.refresh()
        self.http_lastcount={}
        self.ssh_lastcount={}
        self.srcips=[]
    def update_policy(self):
        #ATTENTION: update the policy based on current forward and query policies 
        self.policy = self.forward+self.query
        pass

    def check_redirect(self,p): #ATTENTION: other attributes?
        #ATTENTION: implement check and redirection
        for m in p.keys():
            m=str(m)
            srcip=m.split('srcip\', ')[1].split(')')[0]
            if srcip=='10.1.1.7'or srcip=='10.1.1.6'or srcip in self.srcips:
                continue
            else:
                print m
                self.srcips.append(srcip)
                self.http_lastcount[srcip]=0
                self.ssh_lastcount[srcip]=0
        for ip in self.srcips:
            try:
                current_number_packet=(p[match(dstip='10.1.1.7',dstport=80,srcip=ip)])
                if current_number_packet>self.http_lastcount[ip]+self.threshold_rate and not self.http_lastcount[ip]==-1:
                    print "adding policy"
                    redirect_pol=(match(srcip=ip,dstip='10.1.1.7',dstport=80)>>modify(outport=3))
                    self.policy=if_(match(srcip=ip,dstip='10.1.1.7',dstport=80),redirect_pol,self.policy)#self.policy+redirect_pol
                    #print 'Adding BlackHole Policy to the IP: '+ip
                    self.http_lastcount[ip]=-1
                elif not self.http_lastcount[ip]==-1:
                    self.http_lastcount[ip]=current_number_packet
            except KeyError:
                pass
            try:
                current_number_ssh=(p[match(dstip='10.1.1.6',dstport=22,srcip=ip)])
                #print current_number_ssh
                if current_number_ssh>self.ssh_lastcount[ip]+self.threshold_rate and not self.ssh_lastcount[ip]==-1:
                    redirect_pol_ssh=(match(srcip=ip,dstip='10.1.1.6',dstport=22) >> modify(outport=2))
                    self.policy=if_(match(srcip=ip,dstip='10.1.1.6',dstport=22),redirect_pol_ssh,self.policy)#self.policy+redirect_pol_ssh
                    #print 'Adding BlackHole Policy to the IP: '+ip
                    self.ssh_lastcount[ip]=-1
                elif not self.ssh_lastcount[ip]==-1:
                    self.ssh_lastcount[ip]=current_number_ssh
            except KeyError:
                pass
         
    def refresh_query(self):
        #ATTENTION: reset the query checking for suspicious traffic and register the callback function
        self.query = count_packets(1,['dstip','srcip','dstport'])
        self.query.register_callback(self.check_redirect)


        pass

    def refresh(self):
        #refresh query and policy
        self.refresh_query()
        self.update_policy()
