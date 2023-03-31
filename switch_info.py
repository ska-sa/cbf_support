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
from myssh import MySSH

# ================================================================
# MAIN
# ================================================================
if __name__ == '__main__':
    import sys,os,re,string,curses
    from optparse import OptionParser
    import ConfigParser
    from multiprocessing.pool import ThreadPool
    from collections import defaultdict

    desc = """This script connects to all the CBF Mellanox Spine and Leaf switches via SSH, and retrieves
and displays the specified telemetry information of the switch.
           """
    parser = OptionParser(description=desc)
    parser.set_usage('%prog [options]')
    parser.add_option('-e', dest='enable', action='store_true',
                      help='Put switch in enable mode. Overrides config file setting.')
    parser.add_option('-l', dest='loglevel', type=str, default='INFO',
                      help='Log level: DEBUG,INFO,ERROR,WARINING,FATAL. Default = INFO')
    parser.add_option('--fans', dest='fans', action='store_true',
                      help='Display switch fans status')
    parser.add_option('--temp', dest='temp', action='store_true',
                      help='Display switch system temperature')
    parser.add_option('--alarm-temp', dest='alarm_temp', action='store_true',
                      help='Display switch alarm tempature info')
    parser.add_option('--alarm-cpu', dest='alarm_cpu', action='store_true',
                      help='Display switch alarm for average CPU utilisation')
    parser.add_option('--alarm-pg', dest='alarm_pg', action='store_true',
                      help='Display switch alarm paging activity info')
    parser.add_option('--alarm-diskio', dest='alarm_diskio', action='store_true',
                      help='Display switch alarm O/S disk I/O info')
    opts, args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        exit()

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
    for i in range(16):
        hosts.append('cbfsw-s{}.cbf.mkat.karoo.kat.ac.za'.format(i+1))
    for i in range(24):
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

    def print_info(cmd):
        temperature  = run_threaded_cmd(ssh_list,cmd)
        for data in temperature:
            for line in data:
                print line
            #print '='*64 + '\n' + '='*64 + '\n'
            print '\n' + '|'*64 + '\n'


#############################################################################################################################
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

    #import IPython;IPython.embed()
#    if opts.fans:
#        cmd = 'show fan | include "FAN|PS|==|Module"'
#        all_output = run_threaded_cmd(ssh_list,cmd)
#        for output in all_output:
#            for out in output:                
#                if out.startswith("host"):
#                    print '='*64
#                    print out
#                elif out.startswith("Module"):
#                    print out
#                elif out.startswith("FAN") or out.startswith("PS"):
#                    print out

    if opts.fans:
        cmd = 'show fan'
        temperature  = run_threaded_cmd(ssh_list,cmd)
        print_info(cmd)

    if opts.temp:
        cmd = 'show temperature'
        temperature  = run_threaded_cmd(ssh_list,cmd)
        print_info(cmd)

    if opts.alarm_temp:
        cmd = 'show stats alarm temperature'
        temperature  = run_threaded_cmd(ssh_list,cmd)
        print_info(cmd)

    if opts.alarm_cpu:
        cmd = 'show stats alarm cpu_util_indiv'
        temperature  = run_threaded_cmd(ssh_list,cmd)
        print_info(cmd)

    if opts.alarm_diskio:
        cmd = 'show stats alarm disk_io'
        temperature  = run_threaded_cmd(ssh_list,cmd)
        print_info(cmd)

    if opts.alarm_pg:
        cmd = 'show stats alarm paging'
        temperature  = run_threaded_cmd(ssh_list,cmd)
        print_info(cmd)

           
    close_ssh(ssh_list)

