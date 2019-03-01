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
    def __init__(self, logger=None, compress=True, loglevel='WARNING'):
        '''
        @param logger    Logging object, if none specified one will be created.
        @param compress  Enable/disable compression.
        @param loglevel Log level if no logger is specified.
        '''
        self.ssh = None
        self.transport = None
        self.compress = compress
        self.bufsize = 65536
        self.loglevel = loglevel
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(loglevel)

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
        self.logger.debug('connecting %s@%s:%d' % (username, hostname, port))
        self.hostname = hostname
        self.username = username
        self.port = port
        paramiko_logger = logging.getLogger(paramiko.__name__)
        paramiko_logger.setLevel(self.loglevel)
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(hostname=hostname,
                             port=port,
                             username=username,
                             password=password)
            self.transport = self.ssh.get_transport()
            self.transport.use_compression(self.compress)
            self.logger.info('succeeded: %s@%s:%d' % (username,
                                               hostname,
                                               port))
        except socket.error as e:
            self.transport = None
            self.logger.error('failed: %s@%s:%d: %s' % (username,
                                                 hostname,
                                                 port,
                                                 str(e)))
        except paramiko.BadAuthenticationType as e:
            self.transport = None
            self.logger.error('failed: %s@%s:%d: %s' % (username,
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
        self.logger.debug('running command: (%d) %s' % (timeout, cmd))

        if self.transport is None:
            self.logger.error('no connection to %s@%s:%s' % (str(self.username),
                                                      str(self.hostname),
                                                      str(self.port)))
            return -1, 'ERROR: connection not established\n'

        # Fix the input data.
        input_data = self._run_fix_input_data(input_data)

        # Initialize the session.
        self.logger.debug('initializing the session')
        session = self.transport.open_session()
        session.set_combine_stderr(True)
        session.get_pty()#height=1000)
        #session.exec_command(cmd)
        session.invoke_shell()
        cmds = cmd.split('\n')
        for cmd in cmds:
            session.send(cmd)
            session.send('\n')
            time.sleep(1)
        #session.send('\n')
        output,status = self._run_poll(session, timeout, input_data)
        #status = session.recv_exit_status()
        self.logger.debug('output size %d' % (len(output)))
        self.logger.debug('status %d' % (status))
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
            #self.logger.info('session.exit_status_ready() %s' % str(session.exit_status_ready()))
            self.logger.error('stdin.channel.closed %s' % str(stdin.channel.closed))
            if stdin.channel.closed is False:
                self.logger.debug('sending input data')
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
        self.logger.debug('polling (%d, %d)' % (maxseconds, maxcount))
        start = datetime.datetime.now()
        start_secs = time.mktime(start.timetuple())
        output = ''
        session.setblocking(0)
        status = -1
        while True:
            if session.recv_ready():
                data = session.recv(self.bufsize)
                self.logger.debug(repr(data))
                output += data
                self.logger.debug('read %d bytes, total %d' % (len(data), len(output)))

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
                        self.logger.debug('sending input data %d' % (len(data)))
                        session.send(data)

            #exit_status_ready signal not sent when using 'invoke_shell'
            #self.logger.info('session.exit_status_ready() = %s' % (str(session.exit_status_ready())))
            #if session.exit_status_ready():
            if check_for_prompt(output,prompt) == True:
                status = 0
                break

            # Timeout check
            now = datetime.datetime.now()
            now_secs = time.mktime(now.timetuple()) 
            et_secs = now_secs - start_secs
            self.logger.debug('timeout check %d %d' % (et_secs, maxseconds))
            if et_secs > maxseconds:
                self.logger.debug('polling finished - timeout')
                timeout_flag = True
                break
            time.sleep(0.200)

        self.logger.debug('polling loop ended')
        if session.recv_ready():
            data = session.recv(self.bufsize)
            output += data
            self.logger.debug('read %d bytes, total %d' % (len(data), len(output)))

        self.logger.debug('polling finished - %d output bytes' % (len(output)))
        if timeout_flag:
            self.logger.debug('appending timeout message')
            output += '\nERROR: timeout after %d seconds\n' % (timeout)
            session.close()

        return output, status


