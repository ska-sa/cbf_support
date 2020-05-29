#reduced cpu usage of server
#!/usr/bin/python
'''
This class allows you to run commands on a remote host and provide
input if necessary.

VERSION 1.2
'''
import paramiko
import logging
import socket
import time
import datetime
import re
import pickle
import sys
import threading
import multiprocessing
# import IPython
import logging.handlers as handlers

# CONSTANTS
HEADERSIZE = 10
IPV4 = socket.AF_INET
TCP = socket.SOCK_STREAM
PORT = 12345

logger = logging.getLogger('__name__')
level_info = logging.getLevelName('INFO')
level_debug = logging.getLevelName('DEBUG')
logger.setLevel(level_debug)
# fmt = '%(asctime)s %(funcName)s:%(lineno)d %(message)s'
# fmt = '%(asctime)s %(levelname)s: %(message)s'
fmt = '%(asctime)s %(levelname)s - %(funcName)s: %(message)s'
date_fmt = '%Y-%m-%d %H:%M:%S'
logging_format = logging.Formatter(fmt, date_fmt)

handler = logging.StreamHandler()
handler.setFormatter(logging_format)
handler.setLevel(level_info)
logger.addHandler(handler)

file_handler = handlers.RotatingFileHandler('serverlog.log', maxBytes=10000, backupCount=2)
# file_handler = logging.FileHandler('log.txt')
file_handler.setFormatter(logging_format)
file_handler.setLevel(level_info)
logger.addHandler(file_handler)

# shared_dict = manager.dict({'sd': switch_dict, 'sl': ssh_list, 'mx':matrix})

# def updater(shared_dict):  # switch_dict, ssh_list, matrix
#     # global matrix_global
#     # while True:
#     #     _matrix = get_discard(switch_dict, ssh_list, matrix)
#     #     matrix_global = _matrix
#     a = shared_dict['sd']
#     print 'updater'

# ====================================================================================================================
# class MySSH
# ====================================================================================================================
class MySSH:
    '''
    Create an SSH connection to a server and execute commands.
    Here is a typical usage:

        ssh = MySSH()
        ssh.connect('host', 'user', 'password', port=22)
        if ssh.connected() is False:
            sys.exit('Connection failed')

        # Run a command that does not require input.
        status, output = ssh.run('uname -a')
        print 'status = %d' % (status)
        print 'output (%d):' % (len(output))
        print '%s' % (output)

        # Run a command that does requires input.
        status, output = ssh.run('sudo uname -a', 'sudo-password')
        print 'status = %d' % (status)
        print 'output (%d):' % (len(output))
        print '%s' % (output)
    '''

    def __init__(self, logger, compress=True):
        '''
        @param compress  Enable/disable compression.
        '''
        self.ssh = None
        self.transport = None
        self.compress = compress
        self.bufsize = 65536

        self.info = logger.info
        self.debug = logger.debug
        self.error = logger.error

    def __del__(self):
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    def connect(self, hostname, username, password, port=22):
        '''
        Connect to the host.

        @param hostname  The hostname.
        @param username  The username.
        @param password  The password.
        @param port      The port (default=22).

        @returns True if the connection succeeded or false otherwise.
        '''
        self.debug('connecting %s@%s:%d' % (username, hostname, port))
        self.hostname = hostname
        self.username = username
        self.port = port
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(hostname=hostname,
                             port=port,
                             username=username,
                             password=password)
            self.transport = self.ssh.get_transport()
            self.transport.use_compression(self.compress)
            self.info('succeeded: %s@%s:%d' % (username,
                                               hostname,
                                               port))
        except socket.error as e:
            self.transport = None
            self.error('failed: %s@%s:%d: %s' % (username,
                                                 hostname,
                                                 port,
                                                 str(e)))
        except paramiko.BadAuthenticationType as e:
            self.transport = None
            self.error('failed: %s@%s:%d: %s' % (username,
                                                 hostname,
                                                 port,
                                                 str(e)))

        return self.transport is not None

    # def run(self, cmd, input_data=' ', timeout=10):
    def run(self, cmd, input_data=' ', timeout=30):
        '''
        Run a command with optional input data.

        Here is an example that shows how to run commands with no input:

            ssh = MySSH()
            ssh.connect('host', 'user', 'password')
            status, output = ssh.run('uname -a')
            status, output = ssh.run('uptime')

        Here is an example that shows how to run commands that require input:

            ssh = MySSH()
            ssh.connect('host', 'user', 'password')
            status, output = ssh.run('sudo uname -a', '<sudo-password>')

        @param cmd         The command to run.
        @param input_data  The input data (default is None).
        @param timeout     The timeout in seconds (default is 10 seconds).
        @returns The status and the output (stdout and stderr combined).
        '''
        self.debug('running command: (%d) %s' % (timeout, cmd))

        if self.transport is None:
            self.error('no connection to %s@%s:%s' % (str(self.username),
                                                      str(self.hostname),
                                                      str(self.port)))
            return -1, 'ERROR: connection not established\n'

        # Fix the input data.
        input_data = self._run_fix_input_data(input_data)

        # Initialize the session.
        self.debug('initializing the session')
        session = self.transport.open_session()
        session.set_combine_stderr(True)
        session.get_pty()  # height=1000)
        # session.exec_command(cmd)
        session.invoke_shell()
        session.send(cmd)
        session.send('\n')
        output, status = self._run_poll(session, timeout, input_data)
        #ooutput, status = self._run_poll(session, timeout, input_data)
        ##########################################
        # if len(output) < 3000:
        #     for i in range(0, 5):
        #         output, status = self._run_poll(session, timeout, input_data)
        #         if len(output) > 3000:
        #             break
        ##########################################
        # status = session.recv_exit_status()
        self.debug('output size %d' % (len(output)))
        self.debug('status %d' % (status))
        return status, output

    def connected(self):
        '''
        Am I connected to a host?

        @returns True if connected or false otherwise.
        '''
        return self.transport is not None

    def _run_fix_input_data(self, input_data):
        '''
        Fix the input data supplied by the user for a command.

        @param input_data  The input data (default is None).
        @returns the fixed input data.
        '''
        if input_data is not None:
            if len(input_data) > 0:
                if '\\n' in input_data:
                    # Convert \n in the input into new lines.
                    lines = input_data.split('\\n')
                    input_data = '\n'.join(lines)
            return input_data.split('\n')
        return []

    def _run_send_input(self, session, stdin, input_data):
        '''
        Send the input data.

        @param session     The session.
        @param stdin       The stdin stream for the session.
        @param input_data  The input data (default is None).
        '''
        if input_data is not None:
            # self.info('session.exit_status_ready() %s' % str(session.exit_status_ready()))
            self.error('stdin.channel.closed %s' % str(stdin.channel.closed))
            if stdin.channel.closed is False:
                self.debug('sending input data')
                stdin.write(input_data)

    def _run_poll(self, session, timeout, input_data, prompt=[' > ', ' # ']):
        '''
        Poll until the command completes.

        @param session     The session.
        @param timeout     The timeout in seconds.
        @param input_data  The input data.
        @returns the output
        '''

        def check_for_prompt(output, prompt):
            for prmt in prompt:
                # Only check last 3 characters in return string
                if output[-3:].find(prmt) > -1:
                    return True
            return False

        interval = 0.1
        maxseconds = timeout
        maxcount = maxseconds / interval

        # Poll until completion or timeout
        # Note that we cannot directly use the stdout file descriptor
        # because it stalls at 64K bytes (65536).
        input_idx = 0
        timeout_flag = False
        self.debug('polling (%d, %d)' % (maxseconds, maxcount))
        start = datetime.datetime.now()
        start_secs = time.mktime(start.timetuple())
        output = ''
        session.setblocking(0)
        status = -1
        while True:
            if session.recv_ready():
                data = session.recv(self.bufsize)
                self.debug(repr(data))
                output += data
                self.debug('read %d bytes, total %d' % (len(data), len(output)))

                if session.send_ready():
                    # We received a potential prompt.
                    # In the future this could be made to work more like
                    # pexpect with pattern matching.

                    # If 'lines 1-45' found in ouput, send space to the pty
                    # to trigger the next page of output. This is needed if
                    # more that 24 lines are sent (default pty height)
                    pattern = re.compile('lines \d+-\d+')

                    if re.search(pattern, output):
                        session.send(' ')
                    elif input_idx < len(input_data):
                        data = input_data[input_idx] + '\n'
                        input_idx += 1
                        self.debug('sending input data %d' % (len(data)))
                        session.send(data)

            # exit_status_ready signal not sent when using 'invoke_shell'
            # self.info('session.exit_status_ready() = %s' % (str(session.exit_status_ready())))
            # if session.exit_status_ready():
            if check_for_prompt(output, prompt) == True:
                status = 0
                break

            # Timeout check
            now = datetime.datetime.now()
            now_secs = time.mktime(now.timetuple())
            et_secs = now_secs - start_secs
            self.debug('timeout check %d %d' % (et_secs, maxseconds))
            if et_secs > maxseconds:
                self.debug('polling finished - timeout')
                timeout_flag = True
                break
            time.sleep(0.200)

        self.debug('polling loop ended')
        if session.recv_ready():
            data = session.recv(self.bufsize)
            output += data
            self.debug('read %d bytes, total %d' % (len(data), len(output)))

        self.debug('polling finished - %d output bytes' % (len(output)))
        if timeout_flag:
            self.debug('appending timeout message')
            output += '\nERROR: timeout after %d seconds\n' % (timeout)
            session.close()

        return output, status # 'Last login: Tue Mar 31 21:49:04 2020 from 10.1.42.50Mellanox Switchterminal type dumbshow lldp interfaces ethernet remote | include "Eth|Remote system name"'

# ===================================================================================================================
# End of class MySSH
# ===================================================================================================================

# ===================================================================================================================
# MAIN
# ===================================================================================================================
if __name__ == '__main__':
    import sys, os, re, string, curses
    from optparse import OptionParser
    import ConfigParser
    from multiprocessing.pool import ThreadPool
    from collections import defaultdict

    desc = """This programs connects to Mellanox switches via SSH and maps connections
              between switches and hosts using LLDP. Switch rates are read and displayed
              in a matrix. 
              Press 'c' to clear counters. (must enable admin mode) 
              Press ctrl-c to exit program.
           """
    parser = OptionParser(description=desc)
    parser.set_usage('%prog [options]')
    parser.add_option('-l', dest='loglevel', type=str, default='INFO', # changed from INFO to DEBUG
                      help='Log level: DEBUG,INFO,ERROR,WARINING,FATAL. Default = INFO')
    parser.add_option('-a', '--maxleaves', type=int, default=36,
                      help='Number of leaf switches in the system.')
    parser.add_option('-p', '--maxspines', type=int, default=18,
                      help='Number of spine switches in the system.')
    parser.add_option('-n', '--numsw', type=int, default=36,
                      help='Number of switches to process.')
    parser.add_option('-t', '--startswitch', type=int, default=1,
                      help='Start displaying from specified switch.')
    parser.add_option('-d', '--display', type=str, default='leaves',  # changed from spines to leaves ^
                      help='Display spines or leaves.')
    parser.add_option('-m', '--admin', action='store_true',
                      help='Connect to switches using admin account')
    opts, args = parser.parse_args()

    # Setup the logger
    # loglevel = opts.loglevel
    # logger = logging.getLogger('mellanox_switch_comms')
    # level = logging.getLevelName(loglevel)
    # logger.setLevel(level)
    # #fmt = '%(asctime)s %(funcName)s:%(lineno)d %(message)s'
    # #fmt = '%(asctime)s %(levelname)s: %(message)s'
    # fmt = '%(asctime)s %(levelname)s %(funcName)s: %(message)s'
    # date_fmt = '%Y-%m-%d %H:%M:%S'
    # logging_format = logging.Formatter(fmt, date_fmt)
    # handler = logging.StreamHandler()
    # handler.setFormatter(logging_format)
    # handler.setLevel(level)
    # logger.addHandler(handler)

    port = 22
    if opts.admin:
        username = 'admin'
        password = 'admin'
    else:
        username = 'monitor'
        password = 'monitor'
    sudo_password = password  # assume that it is the same password
    hosts_leaves = []
    hosts_spines = []
    hosts_all = []

    for i in range(1, 36+1):  # list of leaf switch addresses 1 - 36
        hosts_leaves.append('cbfsw-l{}.cbf.mkat.karoo.kat.ac.za'.format(i))

    for i in range(1, 18+1):  # list of spine switch addresses 1 - 18
        hosts_spines.append('cbfsw-s{}.cbf.mkat.karoo.kat.ac.za'.format(i))

    hosts_all = hosts_leaves + hosts_spines  # leaf and spine switches combined

    matrix_global = 0

# ===================================================================================================================
# FUNCTIONS
# ===================================================================================================================

    def ssh_conn(hostname):
        ssh = MySSH(logger) # create class object, passing logger object
        ssh.connect(hostname=hostname,
                    username=username,
                    password=password,
                    port=port)
        if ssh.connected() is False:
            logger.error('Connection failed.')
            return hostname
        return ssh


    def rem_extra_chars(in_str):
        pat = re.compile('lines \d+-\d+ ')
        in_str = re.sub(pat, '', in_str)
        pat = re.compile('lines \d+-\d+\/\d+ \(END\) ')
        in_str = re.sub(pat, '', in_str)
        return in_str.replace('\r', '')


    def run_cmd(ssh_obj, cmd, indata=None, enable=False):
        '''
        Run a command with optional input.

        @param cmd    The command to execute.
        @param indata The input data.
        @returns The command exit status and output.
                 Stdout and stderr are combined.
        '''
        prn_cmd = cmd
        cmd = 'terminal type dumb\n' + cmd
        if enable:
            cmd = 'enable\n' + cmd

        output = ''
        output += ('\n' + '=' * 64 + '\n')
        output += ('host    : ' + ssh_obj.hostname + '\n')
        output += ('command : ' + prn_cmd + '\n')
        status, outp = ssh_obj.run(cmd, indata, timeout=30)
        #status, outp = ssh_obj.run(cmd, indata, timeout=?)
        output += ('status  : %d' % (status) + '\n')
        output += ('output  : %d bytes' % (len(output)) + '\n')
        output += ('=' * 64 + '\n')
        outp = rem_extra_chars(outp)
        output += outp
        x = output
        return output


    def run_threaded_cmd(ssh_list, cmd, enable=False):
        '''
        Run threaded command on all clients in ssh_list
        '''
        thread_obj = [0] * len(ssh_list)  # create list of zeros with length same as ssh_list
        pool = ThreadPool(processes=len(ssh_list))
        output = []
        for i, ssh_obj in enumerate(ssh_list):  # execute each thread
            thread_obj[i] = pool.apply_async(run_cmd, args=(ssh_obj, cmd), kwds={'enable': enable})
        for i, ssh_obj in enumerate(ssh_list):  # retrieve/get data from each thread
            output.append(thread_obj[i].get())
            x = thread_obj[i].get()
        pool.close()
        pool.join()
        return [x.split('\n') for x in
                output]  # list comprehension splits string into multiple strings at '\n', and stores in list


    def close_ssh(ssh_list):
        thread_obj = [0] * len(ssh_list)
        pool = ThreadPool(processes=len(ssh_list))
        logger.info('Closing SSH connections')
        for i, ssh_obj in enumerate(ssh_list):
            thread_obj[i] = pool.apply_async(ssh_obj.ssh.close)
        for i, ssh_obj in enumerate(ssh_list):
            thread_obj[i].get()
        pool.close()
        pool.join()


    # Natural sort
    def atoi(text):
        return int(text) if text.isdigit() else text


    def natural_keys(text):
        '''
        alist.sort(key=natural_keys) sorts in human order
        last element in return value is empty string if last value in string is a digit
        '''
        value = [atoi(c) for c in re.split('(\d+)', text)]
        return value


    def create_matrix():
        lines = 36 * 2 + 1  # no. of ports displayed = 36
        cols = 36 + 1  # no. of leaf switches displayed = 36
        _matrix = [[[0 for x in range(cols)] for y in range(lines)] for z in range(16)]
        #   creates 3-D matrix, matrix[16][lines][cols]
        return _matrix


    def get_discard(switch_dict, ssh_list, matrix, data_ready, terminate):
        global matrix_global
        global address_list
        while True:
            time.sleep(0.5)
            logger.info('Requesting data from leaf and spine switches...')
            cmd = 'show interface ethernet | include "Rx|Tx|Eth|discard packets|bytes/sec|error packets"'
            all_output = run_threaded_cmd(ssh_list, cmd)
            good_output = False
            timeout = 5
            while not good_output and timeout > 0:
                try:
                    for output in all_output:
                        sw_name_idx = [i for i, s in enumerate(output) if 'CBFSW' in s][0]  # [0] is index of desired element in list comprehension. sw_name_idx is index of element containing CBFSW
                        sw_name = output[sw_name_idx].split(' ')[0].split('-')[-1]  # extracts eg. L28 from string: CBFSW-L28 [standalone: master] > terminal type dumb'
                        for i, line in enumerate(output):
                            if line.startswith('Eth1'):
                                eth = line  # extracts Eth1/36 from output
                            if line.startswith('  60 seconds ingress'):
                                in_rate = line.split(',')[1] # splits into list'  60 seconds ingress rate: 24864 bits/sec, 3108 bytes/sec, 9 packets/sec'
                                in_rate = [int(i) for i in in_rate.split() if i.isdigit()][0] # extract digits, stored as long integer
                            if line.startswith('  60 seconds egress'):
                                egr_rate = line.split(',')[1]  # splits into list'  60 seconds egress rate: 24864 bits/sec, 3108 bytes/sec, 9 packets/sec'
                                egr_rate = [int(i) for i in egr_rate.split() if i.isdigit()][0]  # extract digits, stored as long integer
                            if line.startswith('Rx'):
                                rx_err = output[i + 1].split(' ')  # element after 'Rx'. split string at '' and adds remaining strings to list
                                rx_err = [x for x in rx_err if x != '']  # creates list removing all spaces'' in list
                                rx_err = int(rx_err[0])  # cast string of digits to int
                                rx_disc = output[i + 2].split(' ')  # element after 'Rx'. split string at '' and adds remaining strings to list
                                rx_disc = [x for x in rx_disc if x != '']  # creates list removing all spaces'' in list
                                rx_disc = int(rx_disc[0])  # cast string of digits to int (value of rx discards)
                            if line.startswith('Tx'):
                                tx_err = output[i + 1].split(' ')  # element after 'Tx'. split string at '' and adds remaining strings to list
                                tx_err = [x for x in tx_err if x != '']  # creates list removing all spaces'' in list
                                tx_err = int(tx_err[0])  # cast string of digits to int
                                tx_disc = output[i + 2].split(' ')  # element after 'Tx'. split string at '' and adds remaining strings to list
                                tx_disc = [x for x in tx_disc if x != '']  # creates list removing all spaces'' in list
                                tx_disc = int(tx_disc[0])  # cast string of digits to int (value of tx discards)

                                switch_dict[sw_name][eth]['rx_discard'] = rx_disc  # stores rx discards in switch_dict
                                switch_dict[sw_name][eth]['tx_discard'] = tx_disc  # stores tx discards in switch_dict
                                switch_dict[sw_name][eth]['ingress_rate'] = in_rate  # stores in rate in switch_dict
                                switch_dict[sw_name][eth]['egress_rate'] = egr_rate  # stores out rate in switch_dict
                                switch_dict[sw_name][eth]['rx_err'] = rx_err  # stores rx errors in switch_dict
                                switch_dict[sw_name][eth]['tx_err'] = tx_err  # stores tx errors in switch_dict
                                switch_dict[sw_name][eth]['sw_status'] = time.time()  # stores current time in switch_dict
                                # switch_dict['L9']['Eth1/1']
                    good_output = True
                except (ValueError, IndexError):
                    timeout -= 1

            if timeout == 0:
                # logger.debug('Rx or tx rates not a number, unexpected output from switch: {}'.format(output[i + 1]))
                logger.debug('Rx or tx rates not a number, unexpected output from switch.')


            port_list = []
            lines = 0
            for k, v in switch_dict.iteritems():  # same as .items(), display keys and values
                for port in v.keys():  # port = Eth1/1 or Eth1/n
                    try:
                        port_list.index(port)
                    except ValueError:
                        port_list.append(port)
            port_list = sorted(port_list, key=natural_keys)
            lines = len(port_list) * 2 + 1

            try:
                sorted_swlist = sorted(switch_dict.keys(), key=natural_keys)  # sort keys in switch_dict alphabetically
                sorted_leaves = ['L'+str(x) for x in range(1,37)]  # list of leaf switches [L1 - L36]
                sorted_spines = ['S'+str(x) for x in range(1,19)]  # list of spine switches [S1 - S18]
                first_sw = int(natural_keys(sorted_swlist[0])[-2])  # extracts 1 from 'L1' and casts to int
            except (ValueError, IndexError):
                logger.error('Switch name not end in a number: {}'.format(first_sw))
                close_ssh(ssh_list)
                raise ValueError

            # storing of leaf data in matrix
            for switch in switch_dict.keys(): # ['L1','L2','L3'.....]
                if switch.startswith('L'):
                    idx = sorted_leaves.index(switch) + 1  # gets value of index of leaf switch 'Lx'

                    for port, data in switch_dict[switch].iteritems():
                        try:
                            port_idx = port_list.index(port) + 1

                            matrix[0][0][idx] = switch  # stores name of leaf switch 'Lx' in matrix for column headings
                            matrix[1][0][idx] = switch
                            matrix[2][0][idx] = switch
                            matrix[3][0][idx] = switch
                            matrix[4][0][idx] = switch
                            matrix[5][0][idx] = switch

                            matrix[0][port_idx * 2 - 1][idx] = data['egress_rate']  # values for egress rate
                            matrix[0][port_idx * 2][idx] = data['ingress_rate']  # values for ingress rate

                            matrix[1][port_idx * 2 - 1][idx] = data['rx_err'] - matrix[5][port_idx * 2 - 1][idx]  # values for current rx errors minus prev
                            matrix[1][port_idx * 2][idx] = data['tx_err'] - matrix[5][port_idx * 2][idx]  # values for current tx errors minus prev

                            matrix[2][port_idx * 2 - 1][idx] = data['rx_discard'] - matrix[4][port_idx * 2 - 1][idx] # values for current minus prev rx discards
                            matrix[2][port_idx * 2][idx] = data['tx_discard'] - matrix[4][port_idx * 2][idx]  # values for current minus prev tx discards

                            matrix[3][port_idx * 2 - 1][idx] = data['sw_status']   # values for switch status
                            matrix[3][port_idx * 2][idx] = data['sw_status']  # values for switch status same as above

                            matrix[4][port_idx * 2 - 1][idx] = data['rx_discard']  # prev values for rx discards stored in  matrix[4]
                            matrix[4][port_idx * 2][idx] = data['tx_discard']  # prev values for tx discards stored in  matrix[4]

                            matrix[5][port_idx * 2 - 1][idx] = data['rx_err']  # prev values for rx discards stored in  matrix[5]
                            matrix[5][port_idx * 2][idx] = data['tx_err']  # prev values for tx discards stored in  matrix[5]

                            matrix[0][port_idx * 2 - 1][0] = port[3:] + ' out'  # row headings for ports 1/1 - 1/36
                            matrix[0][port_idx * 2][0] = port[3:] + ' in'  # row headings for ports 1/1 - 1/36

                            ###########################################################
                            # adds spine switch no. 'Sx' to row headings of leaf ports 19-36
                            if port[3:] == '1/19':
                                matrix[0][port_idx * 2 - 1][0] = '1/19->S1'
                            elif port[3:] == '1/20':
                                matrix[0][port_idx * 2 - 1][0] = '1/20->S2'
                            elif port[3:] == '1/21':
                                matrix[0][port_idx * 2 - 1][0] = '1/21->S3'
                            elif port[3:] == '1/22':
                                matrix[0][port_idx * 2 - 1][0] = '1/22->S4'
                            elif port[3:] == '1/23':
                                matrix[0][port_idx * 2 - 1][0] = '1/23->S5'
                            elif port[3:] == '1/24':
                                matrix[0][port_idx * 2 - 1][0] = '1/24->S6'
                            elif port[3:] == '1/25':
                                matrix[0][port_idx * 2 - 1][0] = '1/25->S7'
                            elif port[3:] == '1/26':
                                matrix[0][port_idx * 2 - 1][0] = '1/26->S8'
                            elif port[3:] == '1/27':
                                matrix[0][port_idx * 2 - 1][0] = '1/27->S9'
                            elif port[3:] == '1/28':
                                matrix[0][port_idx * 2 - 1][0] = '1/28->S10'
                            elif port[3:] == '1/29':
                                matrix[0][port_idx * 2 - 1][0] = '1/29->S11'
                            elif port[3:] == '1/30':
                                matrix[0][port_idx * 2 - 1][0] = '1/30->S12'
                            elif port[3:] == '1/31':
                                matrix[0][port_idx * 2 - 1][0] = '1/31->S13'
                            elif port[3:] == '1/32':
                                matrix[0][port_idx * 2 - 1][0] = '1/32->S14'
                            elif port[3:] == '1/33':
                                matrix[0][port_idx * 2 - 1][0] = '1/33->S15'
                            elif port[3:] == '1/34':
                                matrix[0][port_idx * 2 - 1][0] = '1/34->S16'
                            elif port[3:] == '1/35':
                                matrix[0][port_idx * 2 - 1][0] = '1/35->S17'
                            elif port[3:] == '1/36':
                                matrix[0][port_idx * 2 - 1][0] = '1/36->S18'

                            ###########################################################
                            #adding row headings to matrix
                            matrix[1][port_idx * 2 - 1][0] = port[3:] + ' rx err'  # row headings for rx errors
                            matrix[1][port_idx * 2][0] = port[3:] + ' tx err'  # row headings for tx errors
                            matrix[2][port_idx * 2 - 1][0] = port[3:] + ' rx ds'  # row headings for rx discards
                            matrix[2][port_idx * 2][0] = port[3:] + ' tx ds'  # row headings for tx discards
                            matrix[3][port_idx * 2 - 1][0] = port[3:] + ' sw st'  # row headings for switch status
                            matrix[3][port_idx * 2][0] = port[3:] + ' sw st'  # row headings for switch status
                            matrix[4][port_idx * 2 - 1][0] = port[3:] + ' prev rx ds'  # row headings for prev rx discards
                            matrix[4][port_idx * 2][0] = port[3:] + ' prev tx ds'  # row headings for prev tx discards
                            matrix[5][port_idx * 2 - 1][0] = port[3:] + ' prev rx err'  # row headings for prev rx errors
                            matrix[5][port_idx * 2][0] = port[3:] + ' prev tx err'  # row headings for prev tx errors

                        except (IndexError, TypeError):
                            pass

            # storing of spine data in matrix
            for switch in switch_dict.keys():  # ['S1','S2','S3'.....]
                if switch.startswith('S'):
                    idx = sorted_spines.index(switch) + 1  # gets value of index of spine switch 'Sx'

                    for port, data in switch_dict[switch].iteritems():  # get keys and values in 'switch_dict' in 'Sx'
                        if data.has_key('remote_switch'):  # has_key returns true if 'remote_switch' is in dictionary
                            rem_sw = re.split('(\d+)', data['remote_switch']) #seperate number/digit and return list

                            try:
                                rem_sw_nr = int(rem_sw[-2])  # [-2] second last index

                            except (ValueError, IndexError):
                                logger.error('Remote switch name from LLDP does not end in a number: {}'.format(data['remote_switch']))
                                close_ssh(ssh_list)
                                raise ValueError
                            #TODO add rates, errors, discards etc. for spines
                            try:
                                matrix[6][0][idx] = switch   # stores name of spine switch 'Sx' in matrix for column headings
                                matrix[7][0][idx] = switch
                                matrix[8][0][idx] = switch
                                matrix[9][0][idx] = switch
                                matrix[10][0][idx] = switch
                                matrix[11][0][idx] = switch

                                matrix[6][rem_sw_nr * 2 - 1][idx] = data['ingress_rate']  # values for ingress rate
                                matrix[6][rem_sw_nr * 2][idx] = data['egress_rate']  # values for egress rate

                                matrix[7][rem_sw_nr * 2 - 1][idx] = data['tx_err'] - matrix[11][rem_sw_nr * 2 - 1][idx]  # values for current tx errors minus prev
                                matrix[7][rem_sw_nr * 2][idx] = data['rx_err'] - matrix[11][rem_sw_nr * 2][idx]  # values for current rx errors minus prev

                                matrix[8][rem_sw_nr * 2 - 1][idx] = data['tx_discard'] - matrix[10][rem_sw_nr * 2 - 1][idx]  # values for current minus prev tx discards
                                matrix[8][rem_sw_nr * 2][idx] = data['rx_discard'] - matrix[10][rem_sw_nr * 2][idx]  # values for current minus prev rx discards

                                matrix[9][rem_sw_nr * 2 - 1][idx] = data['sw_status']  # values for switch status
                                matrix[9][rem_sw_nr * 2][idx] = data['sw_status']  # values for switch status, same as above

                                matrix[10][rem_sw_nr * 2 - 1][idx] = data['tx_discard']  # prev values for tx discards stored in  matrix[10]
                                matrix[10][rem_sw_nr * 2][idx] = data['rx_discard']  # prev values for rx discards stored in  matrix[10]

                                matrix[11][rem_sw_nr * 2 - 1][idx] = data['tx_err']  # prev values for tx discards stored in  matrix[11]
                                matrix[11][rem_sw_nr * 2][idx] = data['rx_err']  # prev values for rx discards stored in  matrix[11]

                                #############################
                                # adding row headings to matrix
                                matrix[6][rem_sw_nr * 2 - 1][0] = 'L' + str(rem_sw_nr) + ' out'
                                matrix[6][rem_sw_nr * 2][0] = 'L' + str(rem_sw_nr) + ' in'
                                matrix[7][rem_sw_nr * 2 - 1][0] = 'L' + str(rem_sw_nr) + ' tx err'
                                matrix[7][rem_sw_nr * 2][0] = 'L' + str(rem_sw_nr) + ' rx err'
                                matrix[8][rem_sw_nr * 2 - 1][0] = 'L' + str(rem_sw_nr) + ' tx ds'
                                matrix[8][rem_sw_nr * 2][0] = 'L' + str(rem_sw_nr) + ' rx ds'
                                matrix[9][rem_sw_nr * 2 - 1][0] = 'L' + str(rem_sw_nr) + ' sw st'
                                matrix[9][rem_sw_nr * 2][0] = 'L' + str(rem_sw_nr) + ' sw st'
                                matrix[10][rem_sw_nr * 2 - 1][0] = 'L' + str(rem_sw_nr) + ' prev tx ds'
                                matrix[10][rem_sw_nr * 2][0] = 'L' + str(rem_sw_nr) + ' prev rx ds'
                                matrix[11][rem_sw_nr * 2 - 1][0] = 'L' + str(rem_sw_nr) + ' prev tx err'
                                matrix[11][rem_sw_nr * 2][0] = 'L' + str(rem_sw_nr) + ' prev rx err'

                            except (IndexError, TypeError):
                                pass

            ######################################################################
            #inserting spine rates data with leave rates data into matrix[12]
            matrix[12] = [row[:] for row in matrix[0]]  # create matrix[12], a copy of matrix[0] (leaves rates)

            spine_rates = [[value[column] for row, value in enumerate(matrix[6]) if row%2==1] for column in range(1, 19)]
            # extract spine column ingress data from matrix[6] and store as rows in spine_column 2D matrix

            for a, b in enumerate(range(37, 72, 2)):  # iterate through odd row numbers 37-71 for storing spine info in matrix[12]
                matrix[12][b][1:1+len(spine_rates[a])] = spine_rates[a]  # insert spines column data into matrix[12] rows 37 to 72

            ############################################################################
            # inserting spine errors data with leave errors data into matrix[13]
            matrix[13] = [row[:] for row in matrix[1]]  # create matrix[13], a copy of matrix[1] (leaves errors)

            spine_errors = [[value[column] for row, value in enumerate(matrix[7]) if row>0 and row%2==0] for column in range(1, 19)]
            # extract spine column rx discards from matrix[6] and store as rows in spine_column 2D matrix

            for a, b in enumerate(range(37, 72, 2)):  # iterate through odd row numbers 37-71 for storing spine info in matrix[12]
                matrix[13][b][1:1+len(spine_errors[a])] = spine_errors[a]  # insert spines column data into matrix[12] rows 37 to 72

            #####################################################################
            # inserting spine discards data with leave discards data into matrix[14]
            matrix[14] = [row[:] for row in matrix[2]]  # create matrix[14], a copy of matrix[2] (leaves discards)

            spine_discards = [[value[column] for row, value in enumerate(matrix[8]) if row>0 and row%2==0] for column in range(1, 19)]
            # extract spine column rx errors from matrix[6] and store as rows in spine_column 2D matrix

            for a, b in enumerate(range(37, 72, 2)):  # iterate through odd row numbers 37-71 for storing spine info in matrix[12]
                matrix[14][b][1:1 + len(spine_discards[a])] = spine_discards[a]  # insert spines column data into matrix[12] rows 37 to 72

            #####################################################################
            # inserting spine switch status with leave switch status into matrix[15]
            matrix[15] = [row[:] for row in matrix[3]]  # create matrix[15], a copy of matrix[3] (leaves status)

            spine_status = [[value[column] for row, value in enumerate(matrix[9]) if row>0 and row%2==0] for column in range(1, 19)]
            # extract spine column switch status from matrix[6] and store as rows in spine_column 2D matrix

            for a, b in enumerate(range(37, 72, 2)):  # iterate through odd row numbers 37-71 for storing spine info in matrix[12]
                matrix[15][b][1:1+len(spine_status[a])] = spine_status[a]  # insert spines column data into matrix[12] rows 37 to 72

            # return matrix
            matrix_global = matrix
            data_ready.set()  # data from switches acquired and ready for use
            logger.info('Switch data updated.')
            logger.info('Length of address list: %s', len(address_list))
            logger.info('Addresses: %s', address_list)
            # logger.info('Total No. of threads running: {}.'.format(threading.active_count()))
            logger.info('No. of threads/connections to clients: {}.'.format(threading.active_count() - 48))
            if terminate.is_set():  # exit thread if thread2/handle_client is terminated
                data_ready.clear()
                logger.info('Exiting get_discards()')
                break



    def msg_formatter(data):
        """Returns string consisting of header(length of message) and pickled data."""
        data_pickled = pickle.dumps(data)  # pickle data
        full_msg = str(len(data_pickled)).ljust(HEADERSIZE) + data_pickled  # append header and data to full_msg
        return full_msg

    # #thread2
    # def handle_client(clientsocket, address, s): #('New connection accepted from %s port %s', address, PORT)
    #     global matrix_global
    #     global done_global
    #     logger.info('inside my thread2/handle_client')
    #     while done_global == False:
    #         time.sleep(0.5)
    #     try:
    #         x = matrix_global
    #         msg = msg_formatter(x)  # format msg for sending/tx
    #         clientsocket.send(msg)  # send message
    #         logger.info('Message sent to client %s. Size %s bytes.', address, str(sys.getsizeof(msg)))
    #
    #     except Exception as e:
    #         logger.exception("Generic Error in thread2/handle_client: %s" % e)
    #         # clientsocket.close()
    #         # logger.info('Socket closed')
    #         # logger.debug('thread2/handle_client closing')
    #     finally:
    #         clientsocket.close()
    #         logger.info('Socket closed')
    #         logger.info('thread2/handle_client closing')

    #thread2
    def handle_client(clientsocket, address, s, data_ready, terminate): #('New connection accepted from %s port %s', address, PORT)
        global matrix_global
        global address_list
        address_list.append(address) # add connection to list
        logger.info('inside my thread2/handle_client')
        data_ready.wait() # on 1st run, waits for data to be available from comms()
        try:
            while True:
                x = matrix_global
                msg = msg_formatter(x)  # format msg for sending/tx
                clientsocket.send(msg)  # send message
                logger.info('Message sent to client %s. Size %s bytes.', address, str(sys.getsizeof(msg)))
                time.sleep(4)  # time delay
                if terminate.is_set():  # exit thread if thread2/handle_client is terminated
                    break
        except Exception as e:
            logger.exception("Generic Error in thread2/handle_client: %s" % e)
            # clientsocket.close()
            # logger.info('Socket closed')
            # logger.debug('thread2/handle_client closing')
        finally:
            address_list.remove(address) # remove connection from list
            clientsocket.close()
            logger.info('Socket closed')
            logger.info('Exiting handle_client()')


    # thread1
    # def updater(switch_dict, ssh_list, matrix):
    #     global matrix_global
    #     logger.info('inside my thread1/updater')
    #     #client_connected.wait()  # wait/ block for client connection
    #     try:
    #         while True:
    #             _matrix = get_discard(switch_dict, ssh_list, matrix) #
    #             matrix_global = matrix
    #             data_ready.set()  # on 1st execution of thread, event flag is set and remains set
    #             logger.info('Switch data updated')
    #             # logger.info('Thread1 alive: {}.'.format(thread1.is_alive()))
    #             # logger.info('Thread2 alive: {}.'.format(thread2.is_alive()))
    #             if end_main.is_set()==False:  # exit thread if thread2/handle_client is terminated
    #                 break
    #         #logger.info('thread1/updater closing')
    #     except Exception as e:
    #         logger.exception("Generic Error in thread1/updater: %s" % e)
    #         logger.info('thread1/updater closing')








# ===================================================================================================================
# ===================================================================================================================





    # Main Code
    # Open SSH connections to all hosts

    full_ssh_list = []
    thread_obj = [0] * len(hosts_all)  # [0,0,0,0,0,0.....]
    pool = ThreadPool(processes=len(hosts_all))
    logger.info('Opening ssh connections.')
    for i, host in enumerate(hosts_all):
        thread_obj[i] = pool.apply_async(ssh_conn, args=(host,))
    for i, host in enumerate(hosts_all):
        full_ssh_list.append(thread_obj[i].get())  # append ssh_conn returned objects to full_ssh_list
    pool.close()
    pool.join()
    ssh_list = []
    for i, ssh_obj in enumerate(full_ssh_list):
        if type(ssh_obj) == str:
            logger.error('Connection to {} failed.'.format(ssh_obj))
        else:
            ssh_list.append(ssh_obj) # append only connected objects from full_ssh_list to ssh_list
    logger.info('SSH connections established.')

    test = []
    #################
    for ssh_obj in ssh_list:
        test.append(ssh_obj.hostname)
    ##################

    # Map switches:
    logger.info('Mapping switch connections using LLDP')
    # Create 3 level dictionary for switch info
    switch_dict = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    cmd = 'show lldp interfaces ethernet remote | include "Eth|Remote system name"'
    all_output = run_threaded_cmd(ssh_list, cmd)  # 1st run

    new_ssh_list = []
    for output in all_output:
        try:
            host_name = None
            for ln in output:
                if ln.find('host') != -1:
                    host_name = ln.split()[2]
            sw_name_idx = [i for i, s in enumerate(output) if 'CBFSW' in s][0]
            sw_name = output[sw_name_idx].split(' ')[0].split('-')[-1]
            rem_port_id = [i for i, v in enumerate(output) if 'Remote port-id' in v]
            for idx in rem_port_id:
                eth = output[idx - 1]
                remote = output[idx + 1].split(' ')[-1]
                switch_dict[sw_name][eth]['remote_switch'] = remote
            for ssh_obj in ssh_list:
                if ssh_obj.hostname == host_name:
                    new_ssh_list.append(ssh_obj)
        except IndexError:
            if host_name:
                logger.error('Switch output malformed for {}:\n{}'.format(host_name, output))
            else:
                logger.error('Switch output malformed while mapping switches: {}'.format(output))
            _null = raw_input("Press any key to continue...")

    all_output = run_threaded_cmd(ssh_list, cmd)  # 2nd run
    new_ssh_list = []
    for output in all_output:
        try:
            host_name = None
            for ln in output:
                if ln.find('host') != -1:
                    host_name = ln.split()[2]
            sw_name_idx = [i for i, s in enumerate(output) if 'CBFSW' in s][0]
            sw_name = output[sw_name_idx].split(' ')[0].split('-')[-1]
            rem_port_id = [i for i, v in enumerate(output) if 'Remote port-id' in v]
            for idx in rem_port_id:
                eth = output[idx - 1]
                remote = output[idx + 1].split(' ')[-1]
                switch_dict[sw_name][eth]['remote_switch'] = remote
            for ssh_obj in ssh_list:
                if ssh_obj.hostname == host_name:
                    new_ssh_list.append(ssh_obj)
        except IndexError:
            if host_name:
                logger.error('Switch output malformed for {}:\n{}'.format(host_name, output))
            else:
                logger.error('Switch output malformed while mapping switches: {}'.format(output))
            _null = raw_input("Press any key to continue...")

    logger.info('Done mapping switches.')

    data_ready = threading.Event()
    terminate = threading.Event()

    matrix = create_matrix()  # create empty 3-D matrix
    # matrix = get_discard(switch_dict, ssh_list, matrix)
    # matrix = get_discard(switch_dict, ssh_list, matrix)  # called twice to populate matrix with previous values

    s = socket.socket(IPV4, TCP)  # create socket object
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # allows reuse of address and port

    ## client_connected = threading.Event()

    try:
        # thread1 = threading.Thread(name='thread1', target=get_discard, args=(switch_dict, ssh_list, matrix, data_ready, terminate))
        # thread1.setDaemon(True)
        #thread2 = threading.Thread(target=handle_client, args=(clientsocket, address, s))
        #thread1.start()
        thread1 = threading.Thread(target=get_discard, args=(switch_dict, ssh_list, matrix, data_ready, terminate))
        thread1.setDaemon(True)
        logger.info('Starting get_discards() thread')
        thread1.start()

        s.bind(('0.0.0.0', PORT))  # Binding to '0.0.0.0' or '' allows connections from any IP address:
        s.listen(5)  # queue of 5
        address_list =[]
        logger.info('Server is running.')
        logger.info('Listening for client connections.')
        while True:
            clientsocket, address = s.accept()  # accept connection from client
            logger.info('New connection accepted from %s port %s', address, PORT)
            thread2 = threading.Thread(target=handle_client, args=(clientsocket, address, s, data_ready, terminate))
            logger.info('Starting handle_client() thread')
            thread2.start()

    except socket.error as e:
        #print "Socket Error: %s" % e
        logger.exception("Socket Error: %s" % e)
    except KeyboardInterrupt as e:
        #print("KeyboardInterrupt has been caught.")
        logger.exception("Keyboard Error: %s" % e)
    except Exception as e:
        #print "Generic error: %s" % e
        logger.exception("Generic Error: %s" % e)
    finally:
        terminate.set()
        s.close()
        logger.info('Socket closed')

    exit = True
    close_ssh(ssh_list)

# ===================================================================================================================
# end of MAIN
# ===================================================================================================================


