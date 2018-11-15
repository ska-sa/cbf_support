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


# ================================================================
# class MySSH
# ================================================================
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

    def run(self, cmd, input_data=' ', timeout=10):
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
        session.get_pty()#height=1000)
        #session.exec_command(cmd)
        session.invoke_shell()
        session.send(cmd)
        session.send('\n')
        output,status = self._run_poll(session, timeout, input_data)
        #status = session.recv_exit_status()
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
            #self.info('session.exit_status_ready() %s' % str(session.exit_status_ready()))
            self.error('stdin.channel.closed %s' % str(stdin.channel.closed))
            if stdin.channel.closed is False:
                self.debug('sending input data')
                stdin.write(input_data)

    def _run_poll(self, session, timeout, input_data, prompt=[' > ',' # ']):
        '''
        Poll until the command completes.

        @param session     The session.
        @param timeout     The timeout in seconds.
        @param input_data  The input data.
        @returns the output
        '''
        def check_for_prompt(output,prompt):
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

                    #If 'lines 1-45' found in ouput, send space to the pty 
                    #to trigger the next page of output. This is needed if 
                    #more that 24 lines are sent (default pty height)
                    pattern = re.compile('lines \d+-\d+')

                    if re.search(pattern, output):
                        session.send(' ')
                    elif input_idx < len(input_data):
                        data = input_data[input_idx] + '\n'
                        input_idx += 1
                        self.debug('sending input data %d' % (len(data)))
                        session.send(data)

            #exit_status_ready signal not sent when using 'invoke_shell'
            #self.info('session.exit_status_ready() = %s' % (str(session.exit_status_ready())))
            #if session.exit_status_ready():
            if check_for_prompt(output,prompt) == True:
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

        return output, status



# ================================================================
# MAIN
# ================================================================
if __name__ == '__main__':
    import sys,os,re,string,curses
    from optparse import OptionParser
    import ConfigParser
    from multiprocessing.pool import ThreadPool
    from collections import defaultdict

    desc = """This programs connects to Mellanox switches via SSH and maps connections
              between switches and hosts using LLDP. Switch rates are read and displayed
              in a matrix. Press 'r' to refresh data.
           """
    parser = OptionParser(description=desc)
    parser.set_usage('%prog [options]')
    parser.add_option('-e', dest='enable', action='store_true',
                      help='Put switch in enable mode. Overrides config file setting.')
    parser.add_option('-l', dest='loglevel', type=str, default='INFO',
                      help='Log level: DEBUG,INFO,ERROR,WARINING,FATAL. Default = INFO')
    parser.add_option('-v', '--leaves', type=int, default=24,
                      help='Number of leaf switches in system.')
    parser.add_option('-s', '--spines', type=int, default=16,
                      help='Number of spine switches in system.')
    parser.add_option('-d', '--display', type=str, default='leaves',
                      help='Display spines or leaves.')
    opts, args = parser.parse_args()

    # Setup the logger
    loglevel=opts.loglevel
    logger = logging.getLogger('mellanox_switch_comms')
    level = logging.getLevelName(loglevel)
    logger.setLevel(level)
    #fmt = '%(asctime)s %(funcName)s:%(lineno)d %(message)s'
    fmt = '%(asctime)s %(levelname)s: %(message)s'
    date_fmt = '%Y-%m-%d %H:%M:%S'
    logging_format = logging.Formatter(fmt, date_fmt)
    handler = logging.StreamHandler()
    handler.setFormatter(logging_format)
    handler.setLevel(level)
    logger.addHandler(handler)

    port = 22
    username = 'monitor'
    password = 'monitor'
    sudo_password = password  # assume that it is the same password

    hosts = []
    for i in range(opts.spines):
        hosts.append('cbfsw-s{}.cbf.mkat.karoo.kat.ac.za'.format(i+1))
    for i in range(opts.leaves):
        hosts.append('cbfsw-l{}.cbf.mkat.karoo.kat.ac.za'.format(i+1))

    if opts.enable:
        enable=True
    else:
        enable=False

    def ssh_conn(hostname):
        ssh = MySSH(logger)
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
        return in_str.replace('\r','')

    def run_cmd(ssh_obj, cmd, indata=None):
        '''
        Run a command with optional input.

        @param cmd    The command to execute.
        @param indata The input data.
        @returns The command exit status and output.
                 Stdout and stderr are combined.
        '''
        prn_cmd = cmd
        cmd = 'terminal type dumb\n'+cmd
        if enable:
            cmd = 'enable\n'+cmd

        output = ''
        output += ('\n'+'='*64 + '\n')
        output += ('host    : ' + ssh_obj.hostname + '\n')
        output += ('command : ' + prn_cmd + '\n')
        status, outp = ssh_obj.run(cmd, indata, timeout=30)
        output += ('status  : %d' % (status) + '\n')
        output += ('output  : %d bytes' % (len(output)) + '\n')
        output += ('='*64 + '\n')
        outp = rem_extra_chars(outp)
        output += outp
        return output

    def run_threaded_cmd(ssh_list, cmd):
        '''
        Run threaded command on all clients in ssh_list
        '''
        thread_obj = [0]*len(ssh_list)
        pool = ThreadPool(processes=len(ssh_list))
        output = []
        for i,ssh_obj in enumerate(ssh_list):
            thread_obj[i] = pool.apply_async(run_cmd, args=(ssh_obj,cmd))
        for i,ssh_obj in enumerate(ssh_list):
            output.append(thread_obj[i].get())
        pool.close()
        pool.join()
        return [x.split('\n') for x in output]

    def close_ssh(ssh_list):    
        thread_obj = [0]*len(ssh_list)
        pool = ThreadPool(processes=len(ssh_list))
        logger.info('Closing SSH connections')
        for i,ssh_obj in enumerate(ssh_list):
            thread_obj[i] = pool.apply_async(ssh_obj.ssh.close)
        for i,ssh_obj in enumerate(ssh_list):
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
        value = [ atoi(c) for c in re.split('(\d+)', text) ]
        return value

    def get_switch_map(display, log = True):
        # Map switches:
        if log:
            logger.info('Mapping switch connections using LLDP')
        # Create 3 level dictionary for switch info
        switch_dict = defaultdict(lambda: defaultdict( lambda: defaultdict(list)))
        cmd = 'show lldp interfaces ethernet remote | include "Eth|Remote system name"'
        for i in range(2):
            all_output = run_threaded_cmd(ssh_list,cmd)
            for output in all_output:
                try:
                    sw_name_idx = [i for i,s in enumerate(output) if 'CBFSW' in s][0]
                    sw_name = output[sw_name_idx].split(' ')[0].split('-')[-1]
                    for line in output:
                        if line.startswith('Eth'):
                            eth = line
                        if line.startswith('Remote system'):
                            remote = line.split(' ')[-1]
                            switch_dict[sw_name][eth]['remote_switch'] = remote
                except IndexError:
                    pass
        if log:
            logger.info('Done mapping switches.')
        
        leaves = [x for x in switch_dict.keys() if 'L' in x]
        spines = [x for x in switch_dict.keys() if 'S' in x]
        try:
            max_spine = max([natural_keys(x)[-2] for x in spines])
            max_leaf = max([natural_keys(x)[-2] for x in leaves])
        except:
            logger.error('Switch name did not end in a number. Check names:')
            logger.error('{}'.format(leaves))
            logger.error('{}'.format(spines))
            close_ssh(ssh_list)
            sys.exit()
        if display == 'spines':
            matrix = [[0 for x in range(max_spine+1)] for y in range((max_leaf*2)+1)]
            for k,v in switch_dict.iteritems():
                if k.startswith('S'):
                    spine_nr  = int(natural_keys(k)[-2])
                    matrix[0][spine_nr] = k
                    for port,remote in v.iteritems():
                            if remote.has_key('remote_switch'):
                                rem_sw = remote['remote_switch']
                                if 'CBFSW' in rem_sw: 
                                    rem_sw_num = natural_keys(remote['remote_switch'])[-2]
                                    matrix[rem_sw_num*2-1][0] = rem_sw.split('-')[-1]+' rport'
                                    port_num = int(natural_keys(port)[-2])
                                    if port_num != rem_sw_num:
                                        matrix[rem_sw_num*2-1][spine_nr] = 'error'+port
                                    else:
                                        matrix[rem_sw_num*2-1][spine_nr] = port
                if k.startswith('L'):
                    leaf_nr  = natural_keys(k)[-2]
                    matrix[leaf_nr*2][0] = k+' lport'
                    for port,remote in v.iteritems():
                            if remote.has_key('remote_switch'):
                                rem_sw = remote['remote_switch']
                                if 'CBFSW' in rem_sw: 
                                    rem_sw_num = natural_keys(remote['remote_switch'])[-2]
                                    port_num = int(natural_keys(port)[-2])
                                    if port_num != rem_sw_num+16:
                                        matrix[leaf_nr*2][rem_sw_num] = 'error'+port
                                    else:
                                        matrix[leaf_nr*2][rem_sw_num] = port
        else:
            # Find how many ethernet ports there are on the leaves
            port_list = []
            lines = 0
            for k,v in switch_dict.iteritems():
                for port in v.keys():
                    try:
                        port_list.index(port)
                    except ValueError:
                        port_list.append(port)
            port_list = sorted(port_list,key=natural_keys)
            # TODO: fix this logic, but there should always be 36 linesj
            #lines = len(port_list) + 1
            lines = 36+1
            matrix = [[0 for x in range(max_leaf+1)] for y in range(lines)]
            for k,v in switch_dict.iteritems():
                if k.startswith('L'):
                    leaf_nr  = int(natural_keys(k)[-2])
                    matrix[0][leaf_nr] = k
                    try:
                        for port,remote in v.iteritems():
                                if remote.has_key('remote_switch'):
                                    rem_sw = remote['remote_switch']
                                    port_num = int(natural_keys(port)[-2])
                                    matrix[port_num][0] = port
                                    if rem_sw.startswith('cmc'):
                                        rem_sw = rem_sw.split('.')[0]
                                    matrix[port_num][leaf_nr] = rem_sw
                    except Exception as e:
                        import IPython;IPython.embed()
        return matrix


    def draw(stdscr):
        matrix = get_switch_map(opts.display)
        displeaves = False
        if matrix[0][1].startswith('L'):
            displeaves = True
        # Clear screen
        stdscr.clear()
        lines = curses.LINES
        cols = curses.COLS
        #find max number size in matrix
        max_len =  max([len(str(j)) for i in matrix for j in i])
        colw = max_len + 2
        blank_str = ' '*colw
        m_rows = len(matrix)
        if not displeaves:
            m_rows = m_rows+(m_rows/2)
        else:
            m_rows = m_rows*2
        m_cols = len(matrix[0])
        # Initialise windows and colours
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_WHITE, -1)
        curses.init_pair(2, curses.COLOR_BLACK, -1)
        curses.init_pair(3, curses.COLOR_BLUE, -1)
        curses.init_pair(4, curses.COLOR_BLUE, -1)
        curses.init_pair(5, curses.COLOR_GREEN, -1)
        curses.init_pair(6, curses.COLOR_GREEN, -1)
        curses.init_pair(7, curses.COLOR_RED, -1)
        curses.init_pair(8, curses.COLOR_RED, -1)
        top_cornr = curses.newpad(1,colw)
        col_title = curses.newpad(1, m_cols*colw + colw)
        row_title = curses.newpad(m_rows,colw)
        disp_wind = curses.newpad(m_rows,m_cols*colw)
        top_cornr.addstr(0,0, 'Switch Map', curses.A_BOLD | curses.A_UNDERLINE)
        # Data display block upper left-hand corner
        dminrow = 0
        dmincol = 0
        # Column title upper left-hand corner
        cminrow = 0
        cmincol = 0
        # Row title upper left-hand conrner
        rminrow = 1
        rmincol = 0
        # Data display window
        dwminrow = 1
        dwmincol = colw+1
        dwmaxrow = lines-1
        dwmaxcol = cols-1
        dwrows   = dwmaxrow-dwminrow
        dwcols   = dwmaxcol-dwmincol
        # Column title display window
        ctminrow = 0
        ctmincol = colw+1
        ctmaxrow = 0
        ctmaxcol = cols-1
        # Row title display window
        rtminrow = 1
        rtmincol = 0
        rtmaxrow = lines-1
        rtmaxcol = colw
        stdscr.nodelay(1)
        try:
            redraw = True
            blink = False
            while True:
                if redraw:
                    redraw = False
                    if displeaves:
                        mod = 1
                    else:
                        mod = 2
                    blankc = 0
                    reverse = False
                    for i,row in enumerate(matrix):
                        if i == 0:
                            for j,val in enumerate(row):
                                if val == 0:
                                    val= 'N/C'
                                if j == 0:
                                    pass
                                    #col_title.addstr(i,j, '{}'.format(matrix[0][0]), curses.A_BOLD | curses.A_UNDERLINE)
                                else:
                                    col_title.addstr(i,(j-1)*colw, '{0:>{1}}'.format(val,colw), curses.A_BOLD | curses.A_UNDERLINE)
                        else:
                            for j,val in enumerate(row):
                                if val == 0:
                                    if displeaves:
                                        val = 'N/I'
                                    else:
                                        val = 'N/C'
                                if j == 0:
                                    col_pair = 5
                                    if reverse: col_pair -= 2
                                    row_title.addstr(i+blankc-1,0, val, curses.color_pair(col_pair) | curses.A_BOLD)
                                    if displeaves or (i-1)%mod == 1:
                                        row_title.addstr(i+blankc-1+1,0,' ')
                                else:
                                    if val.startswith('error'):
                                        col_pair = 7
                                        val = val[5:]
                                    else:
                                        col_pair = 5
                                    if reverse: col_pair -= 2
                                    val = '{0:>{1}}'.format(val,colw)
                                    disp_wind.addstr(i+blankc-1,(j-1)*colw, val, curses.color_pair(col_pair))
                                    if displeaves or (i-1)%mod == 1:
                                        disp_wind.addstr(i+blankc-1+1,(j-1)*colw,' ')
                            if displeaves:
                                reverse = not(reverse)
                            if displeaves or (i-1)%mod == 1:
                                blankc += 1

                char = stdscr.getch()
                if char == curses.ERR:
                    if blink:
                        top_cornr.addstr(0,0, 'Switch Map', curses.A_BOLD | curses.A_UNDERLINE | curses.A_REVERSE)
                    else:
                        top_cornr.addstr(0,0, 'Switch Map', curses.A_BOLD | curses.A_UNDERLINE)
                    time.sleep(0.1)
                else:
                    if char == curses.KEY_LEFT: 
                        if dmincol > colw:
                            dmincol -= colw
                        else:
                            dmincol = 0
                    elif char == curses.KEY_RIGHT: 
                        if dmincol < (m_cols-1)*colw - dwcols:
                            dmincol += colw
                        else:
                            dmincol = (m_cols-1)*colw - dwcols
                    elif char == curses.KEY_UP:
                        if dminrow > 0:
                            dminrow -= 1
                        else:
                            dminrow = 0
                    elif char == curses.KEY_DOWN:
                        if dminrow < m_rows-dwrows-2:
                            dminrow += 1
                        else:
                            dminrow = m_rows-dwrows-2
                    elif char == 'r' or 'R':
                        matrix = get_switch_map(opts.display, log = False)
                        redraw = True
                        blink = not(blink)
                # Shift titles with text
                cmincol = dmincol
                rminrow = dminrow
                disp_wind.refresh(dminrow,dmincol,dwminrow,dwmincol,dwmaxrow,dwmaxcol)
                col_title.refresh(cminrow,cmincol,ctminrow,ctmincol,ctmaxrow,ctmaxcol)
                row_title.refresh(rminrow,rmincol,rtminrow,rtmincol,rtmaxrow,rtmaxcol)
                top_cornr.refresh(0,0,0,0,1,colw-1)
        except KeyboardInterrupt:
            return False

    # Main Code
    # Open SSH connections to all hosts
    full_ssh_list = []
    thread_obj = [0]*len(hosts)
    pool = ThreadPool(processes=len(hosts))
    logger.info('Opening ssh connections.')
    for i,host in enumerate(hosts):
        thread_obj[i] = pool.apply_async(ssh_conn, args=(host,))
    for i,host in enumerate(hosts):
        full_ssh_list.append(thread_obj[i].get())
    pool.close()
    pool.join()
    ssh_list = []
    for i,ssh_obj in enumerate(full_ssh_list):
        if type(ssh_obj) == str:
            logger.error('Connection to {} failed.'.format(ssh_obj))
        else:
            ssh_list.append(ssh_obj)
    logger.info('SSH connections established.')

    exit_mode = curses.wrapper(draw)
    #import IPython;IPython.embed()

    close_ssh(ssh_list)

