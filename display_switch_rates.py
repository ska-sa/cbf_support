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
              in a matrix.
           """
    parser = OptionParser(description=desc)
    parser.set_usage('%prog [options]')
    parser.add_option('-l', dest='loglevel', type=str, default='INFO',
                      help='Log level: DEBUG,INFO,ERROR,WARINING,FATAL. Default = INFO')
    parser.add_option('-a', '--maxleaves', type=int, default=36,
                      help='Number of leaf switches in the system.')
    parser.add_option('-p', '--maxspines', type=int, default=18,
                      help='Number of spine switches in the system.')
    parser.add_option('-n', '--numsw', type=int, default=36,
                      help='Number of switches to process.')
    parser.add_option('-t', '--startswitch', type=int, default=1,
                      help='Start displaying from specified switch.')
    parser.add_option('-d', '--display', type=str, default='spines',
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
    strsw = opts.startswitch
    numsw = opts.numsw
    mspines = opts.maxspines
    mleaves = opts.maxleaves
    if opts.display == 'spines':
        if strsw+numsw > mspines+1:
            rng = mspines+1
        else:
            rng = strsw+numsw

        for i in range(strsw,rng):
            hosts.append('cbfsw-s{}.cbf.mkat.karoo.kat.ac.za'.format(i))
    else:
        if strsw+numsw > mleaves+1:
            rng = mleaves + 1
        else:
            rng = strsw+numsw
        for i in range(strsw,rng):
            hosts.append('cbfsw-l{}.cbf.mkat.karoo.kat.ac.za'.format(i))

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

    def run_cmd(ssh_obj, cmd, indata=None, enable=False):
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
        status, outp = ssh_obj.run(cmd, indata, timeout=10)
        output += ('status  : %d' % (status) + '\n')
        output += ('output  : %d bytes' % (len(output)) + '\n')
        output += ('='*64 + '\n')
        outp = rem_extra_chars(outp)
        output += outp
        return output

    def run_threaded_cmd(ssh_list, cmd, enable=False):
        '''
        Run threaded command on all clients in ssh_list
        '''
        thread_obj = [0]*len(ssh_list)
        pool = ThreadPool(processes=len(ssh_list))
        output = []
        for i,ssh_obj in enumerate(ssh_list):
            thread_obj[i] = pool.apply_async(run_cmd, args=(ssh_obj,cmd), kwds={'enable':enable})
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

    def get_rates(switch_dict, ssh_list):

        # Get switch rates:
        speed_exp = ['B/s','KB/s','MB/s','GB/s']
        cmd = 'show interface ethernet rates'
        good_output = False
        #timeout = 5
        #while not good_output and timeout > 0:
        try:
            all_output = run_threaded_cmd(ssh_list,cmd)
            for output in all_output:
                sw_name_idx = [i for i,s in enumerate(output) if 'CBFSW' in s][0]
                sw_name = output[sw_name_idx].split(' ')[0].split('-')[-1]
                rates = [filter(None,output[y].split(' ')) for y in [i for i,s in enumerate(output) if 'Eth' in s]]
                for line in rates:
                    eth = line[0]
                    egress  = float(line[1])*(1000**(speed_exp.index(line[2])))
                    ingress = float(line[4])*(1000**(speed_exp.index(line[5])))
                    switch_dict[sw_name][eth]['egress'] = egress
                    switch_dict[sw_name][eth]['ingress'] = ingress
            good_output = True
        except (ValueError,IndexError):
            pass
                #        timeout -= 1
        #if timeout == 0:
        #    logger.error('Malformed switch output... trying again')

        # Create rates matrix
        cols = len(switch_dict.keys())+1
        if opts.display == 'spines':
            lines = mleaves*2 + 1
        else:
            # Find how many ethernet ports there are on the leavs
            port_list = []
            lines = 0
            for k,v in switch_dict.iteritems():
                for port in v.keys():
                    try:
                        port_list.index(port)
                    except ValueError:
                        port_list.append(port)
            port_list = sorted(port_list,key=natural_keys)
            lines = len(port_list)*2 + 1
        matrix = [[0 for x in range(cols)] for y in range(lines)]
        try:
            sorted_swlist = sorted(switch_dict.keys(),key=natural_keys)
            first_sw = int(natural_keys(sorted_swlist[0])[-2])
        except (ValueError,IndexError):
            logger.error('Switch name not end in a number: {}'.format(first_sw))
            close_ssh(ssh_list)
            raise ValueError
        for switch in switch_dict.keys():
            idx = sorted_swlist.index(switch)+1
            for port,data in switch_dict[switch].iteritems():
                if opts.display == 'spines':
                    if data.has_key('remote_switch'):
                        rem_sw = re.split('(\d+)',data['remote_switch'])
                        try:
                            rem_sw_nr = int(rem_sw[-2])
                        except (ValueError,IndexError):
                            logger.error('Remote switch name from LLDP does not end in a number: {}'.format(data['remote_switch']))
                            close_ssh(ssh_list)
                            raise ValueError
                        try:
                            matrix[0][idx] = switch
                            matrix[rem_sw_nr*2-1][idx] = data['egress']
                            matrix[rem_sw_nr*2][idx] = data['ingress']
                            matrix[rem_sw_nr*2-1][0] = 'L'+str(rem_sw_nr)+' out'
                            matrix[rem_sw_nr*2][0] = 'L'+str(rem_sw_nr)+'  in'
                        except IndexError:
                            pass
                else:
                    try:
                        port_idx = port_list.index(port)+1
                        matrix[0][idx] = switch
                        matrix[port_idx*2-1][idx] = data['ingress']
                        matrix[port_idx*2][idx] = data['egress']
                        matrix[port_idx*2-1][0] = port[3:]+' out'
                        matrix[port_idx*2][0] = port[3:]+'  in'
                    except IndexError:
                        pass
        return matrix

    def draw(stdscr,switch_dict, ssh_list):
        from decimal import Decimal

        def fexp(number):
            (sign, digits, exponent) = Decimal(number).as_tuple()
            return len(digits) + exponent - 1

        def fman(number):
            return Decimal(number).scaleb(-fexp(number)).normalize()

        # Clear screen
        stdscr.clear()
        lines = curses.LINES
        cols = curses.COLS
        matrix = get_rates(switch_dict, ssh_list)
        #prev_matrix = matrix
        m_rows = len(matrix)
        m_rows = m_rows+(m_rows/2)
        m_cols = len(matrix[0])
        #find max number size in matrix
        max_num =  max([x for x in [j for i in matrix for j in i] if isinstance(x,int)])
        colw = fexp(max_num) + 1
        if colw < 9: colw=9
        blank_str = ' '*colw
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
        col_title = curses.newpad(1, m_cols*colw)
        row_title = curses.newpad(m_rows,colw)
        disp_wind = curses.newpad(m_rows,m_cols*colw)
        top_cornr = curses.newpad(1,colw)
        top_cornr.addstr(0,0, 'Rates', curses.A_BOLD | curses.A_UNDERLINE)
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
            data_rdy = True
            blink = True
            pool = ThreadPool(processes=1)
            while True:
                if data_rdy:
                    data_rdy = False
                    thread_obj = pool.apply_async(get_rates, args=(switch_dict, ssh_list))
                    blankc = 0
                    reverse = False
                    for i,row in enumerate(matrix):
                        if i == 0:
                            for j,val in enumerate(row):
                                if j == 0:
                                    pass
                                    #col_title.addstr(i,j, 'Switch', curses.A_BOLD | curses.A_UNDERLINE)
                                else:
                                    col_title.addstr(i,(j-1)*colw, '{0:>{1}}'.format(val,colw), curses.A_BOLD | curses.A_UNDERLINE)
                        else:
                            for j,val in enumerate(row):
                                if j == 0:
                                    if val == 0:
                                        val = 'N/C'
                                    col_pair = 1
                                    if reverse: col_pair += 1
                                    row_title.addstr(i+blankc-1,0, val, curses.color_pair(col_pair) | curses.A_BOLD)
                                    if (i-1)%2 == 1:
                                        row_title.addstr(i+blankc-1+1,0,' ')
                                else:
                                    width = colw-2
                                    if not val:
                                        val = 0
                                    man = fman(val)
                                    exp = fexp(val)
                                    if exp < 3:
                                        col_pair = 1
                                        if reverse: col_pair += 1
                                        rate = 'Bs'
                                        val = '{0:>{1}} {2}'.format(int(val),width-1,rate)
                                    elif exp < 6:
                                        col_pair = 1
                                        if reverse: col_pair += 1
                                        rate = 'KB'
                                        man *= 10**(exp-3)
                                        man = man.normalize()
                                        if width-8 < 0:
                                            val = '{0:>{1}} {2}'.format(int(man),width-1,rate)
                                        else:
                                            val = '{0:{1}.1f} {2}'.format(man,width-1,rate)
                                    elif exp < 9:
                                        col_pair = 3
                                        if reverse: col_pair += 1
                                        rate = 'MB'
                                        man *= 10**(exp-6)
                                        man = man.normalize()
                                        if width-8 < 0:
                                            val = '{0:>{1}} {2}'.format(int(man),width-1,rate)
                                        else:
                                            val = '{0:{1}.1f} {2}'.format(man,width-1,rate)
                                    elif exp < 12:
                                        if man > 4.8:
                                            col_pair = 7
                                            if reverse: col_pair += 1
                                            col_title.addstr(0,(j-1)*colw, '{0:>{1}}'.format(matrix[0][j],colw), curses.color_pair(col_pair) | curses.A_BOLD | curses.A_UNDERLINE)
                                            row_title.addstr(i+blankc-1,0, matrix[i][0], curses.color_pair(col_pair) | curses.A_BOLD)
                                        else:
                                            col_pair = 5
                                            if reverse: col_pair += 1
                                        rate = 'GB'
                                        man *= 10**(exp-9)
                                        man = man.normalize()
                                        val = '{0:{1}.1f} {2}'.format(man,width-1,rate)
                                    else:
                                        col_pair = 1
                                        rate = 'Bs'
                                        val = '{0:>{1}} {2}'.format(int(val),width-1,rate)
                                    disp_wind.addstr(i+blankc-1,(j-1)*colw, val, curses.color_pair(col_pair))
                                    if (i-1)%2 == 1:
                                        disp_wind.addstr(i+blankc-1+1,(j-1)*colw,' ')
                            if (i-1)%2 == 1:
                                blankc += 1
                                reverse = False #not(reverse)
                    #prev_matrix = matrix
                else:
                    char = stdscr.getch()
                    if char == curses.ERR:
                        try:
                            if thread_obj.ready():
                                matrix = thread_obj.get()
                                data_rdy = True
                                if blink:
                                    top_cornr.addstr(0,0, 'Rates', curses.A_BOLD | curses.A_UNDERLINE | curses.A_REVERSE)
                                else:
                                    top_cornr.addstr(0,0, 'Rates', curses.A_BOLD | curses.A_UNDERLINE)
                                blink = not(blink)
                            else:
                                time.sleep(0.1)
                        except:
                            return False
                    else:
                        redraw = True
                        if char == curses.KEY_LEFT: 
                            if dmincol > colw:
                                dmincol -= colw
                            else:
                                dmincol = 0
                        elif char == curses.KEY_RIGHT: 
                            if dmincol < (m_cols-2)*colw - dwcols:
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
                # Shift titles with text
                cmincol = dmincol
                rminrow = dminrow
                disp_wind.refresh(dminrow,dmincol,dwminrow,dwmincol,dwmaxrow,dwmaxcol)
                col_title.refresh(cminrow,cmincol,ctminrow,ctmincol,ctmaxrow,ctmaxcol)
                row_title.refresh(rminrow,rmincol,rtminrow,rtmincol,rtmaxrow,rtmaxcol)
                top_cornr.refresh(0,0,0,0,1,colw-1)
        except KeyboardInterrupt:
            return True

    # Main Code
    # Open SSH connections to all hosts
    exit = False
    while not exit:
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


        # Map switches:
        logger.info('Mapping switch connections using LLDP')
        # Create 3 level dictionary for switch info
        switch_dict = defaultdict(lambda: defaultdict( lambda: defaultdict(list)))
        cmd = 'show lldp interfaces ethernet remote | include "Eth|Remote system name"'
        all_output = run_threaded_cmd(ssh_list,cmd)
        new_ssh_list = []
        for output in all_output:
            try:
                host_name = None
                for ln in output:
                    if 'host ' in ln:
                        host_name = ln.split()[2]
                sw_name_idx = [i for i,s in enumerate(output) if 'CBFSW' in s][0]
                sw_name = output[sw_name_idx].split(' ')[0].split('-')[-1]
                rem_port_id = [i for i,v in enumerate(output) if 'Remote port-id' in v]
                for idx in rem_port_id:
                    eth = output[idx-1]
                    remote = output[idx+1].split(' ')[-1]
                    switch_dict[sw_name][eth]['remote_switch'] = remote
                for ssh_obj in ssh_list:
                    if ssh_obj.hostname == host_name:
                        new_ssh_list.append(ssh_obj)
        
            except IndexError:
                if host_name:
                    logger.error('Switch output malformed for {}:\n{}'.format(host_name,output))
                else:
                    logger.error('Switch output malformed while mapping switches: {}'.format(output))
                _null = raw_input("Press any key to continue...")
        logger.info('Done mapping switches.')

        #matrix = get_rates(switch_dict, new_ssh_list)
        curses.wrapper(draw, switch_dict, new_ssh_list)
        exit = True

        close_ssh(ssh_list)

