import re, logging
from myssh import MySSH
from multiprocessing.pool import ThreadPool


class SwitchComms:
    def __init__(self, logger=None, ssh_port=22, ssh_username='admin', ssh_password='admin'):
        if not(logger):
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger
        self.port = ssh_port
        self.username = ssh_username
        self.password = ssh_password

    def _ssh_conn(self, hostname, loglevel='WARNING'):
        ssh = MySSH(loglevel = loglevel)
        ssh.connect(hostname=hostname,
                    username=self.username,
                    password=self.password,
                    port=self.port)
        if ssh.connected() is False:
            self.logger.error('Connection failed.')
            return None
        return ssh
    
    def _rem_extra_chars(self, in_str):
        pat = re.compile('lines \d+-\d+ ')
        in_str = re.sub(pat, '', in_str)
        pat = re.compile('lines \d+-\d+\/\d+ \(END\) ')
        in_str = re.sub(pat, '', in_str)
        return in_str.replace('\r','')

    def _run_cmd(self, ssh_obj, cmd, indata=None, enable=False, conf_term=False, timeout=60):
        '''
        Run a command with optional input.

        @param cmd    The command to execute.
        @param indata The input data.
        @returns The command exit status and output.
                 Stdout and stderr are combined.
        '''

        prn_cmd = cmd
        if conf_term:
            cmd = 'terminal type dumb\nenable\nconfigure terminal\n'+cmd
        elif enable:
            cmd = 'terminal type dumb\nenable\n'+cmd
        else:
            cmd = 'terminal type dumb\n'+cmd
        output = ''
        output += ('\n'+'='*64 + '\n')
        output += ('host    : ' + ssh_obj.hostname + '\n')
        output += ('command : ' + prn_cmd + '\n')
        status, outp = ssh_obj.run(cmd, indata, timeout=timeout)
        output += ('status  : %d' % (status) + '\n')
        output += ('output  : %d bytes' % (len(output)) + '\n')
        output += ('='*64 + '\n')
        outp = self._rem_extra_chars(outp)
        output += outp
        return output

    def open_connections(self, hosts):
        '''
        Opens ssh connections to all hosts
        @param hosts: list of hosts
        @returns: list of ssh objects of type MySSH
        '''
        ssh_list = []
        thread_obj = [0]*len(hosts)
        pool = ThreadPool(processes=len(hosts))
        err_hosts = hosts[:]
        for i,host in enumerate(hosts):
            thread_obj[i] = pool.apply_async(self._ssh_conn, args=(host,))
        for i,host in enumerate(hosts):
            obj = thread_obj[i].get()
            if obj != None:
                ssh_list.append(obj)
                self.logger.info('Connected to {}'.format(obj.hostname))
                err_hosts.remove(obj.hostname)
        for host in err_hosts:
            self.logger.error('Could not connect to {}'.format(host))
        return ssh_list

    def execute_commands(self, ssh_list, cmds, concurrent=False, enable=False, conf_term=False, timeout=60):
        '''
        Excecutes commands on switches
        @param ssh_list: list of connected MySSH objects
        @param cmds: list of commands to run
        @param concurrent: run each set of commands concurrently on each ssh connection
        @param enable: put switches in enable mode
        @param conf_term: put switches in configure terminal mode (switch will be put in enable mode first)
        @param timeout: ssh command timeout
        @returns: list of text strings returned by switches
        '''
        
        if type(cmds) != list:
            self.logger.error('Commands not sent as a list')
            return False
        ret = []
        pool = ThreadPool(processes=len(ssh_list))
        thread_obj = [0]*len(ssh_list)
        if concurrent:
            all_cmds = ''
            for cmd in cmds:
                all_cmds += cmd+'\n'
            for i,ssh_obj in enumerate(ssh_list):
                thread_obj[i] = pool.apply_async(self._run_cmd, args=(ssh_obj,all_cmds), kwds={'enable':enable,'conf_term':conf_term, 'timeout':timeout})
            for i,ssh_obj in enumerate(ssh_list):
                ret.append(thread_obj[i].get())
            return ret
        else:
            for cmd in cmds:
                for i,ssh_obj in enumerate(ssh_list):
                    thread_obj[i] = pool.apply_async(self._run_cmd, args=(ssh_obj,cmd), kwds={'enable':enable,'conf_term':conf_term, 'timeout':timeout})
                for i,ssh_obj in enumerate(ssh_list):
                    ret.append(thread_obj[i].get())
            return ret

    def close_ssh(self,ssh_list):
        self.logger.info('Closing SSH connections')
        pool = ThreadPool(processes=len(ssh_list))
        thread_obj = [0]*len(ssh_list)
        for i,ssh_obj in enumerate(ssh_list):
            thread_obj[i] = pool.apply_async(ssh_obj.ssh.close)




