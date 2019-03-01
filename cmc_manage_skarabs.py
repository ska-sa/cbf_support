#!/usr/bin/python

import logging  
#from logging.config import fileConfig
#fileConfig('cmc_manage_skarabs_logging_config.ini')  

#logging.basicConfig()
formatter = logging.Formatter('%(levelname)-8s %(message)s')
handler   = logging.StreamHandler()
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(handler)

class MasterCMCUndefined(Exception):
    """Raised when CMC master is not defined."""
    pass

class CMCNoConnection(Exception):
    """Raised when CMC master is not defined."""
    pass

class ManageSkarabs:

    def __init__(self, servers, skarab_map = None, master=None):
        self.servers = servers
        self.skarab_map = skarab_map
        if master:
            if master not in self.servers:
                raise ValueError('Master CMC not in list CMC servers.')
        self.master = master
        self.locked = dict((k,False) for k in self.servers)
        self.lock_entity = 'cmc_manage_script'

    def connect_to_servers(self):
        from katcpclient import KATCPClient

        servers = {}
        for server in self.servers:
            servers[server] = KATCPClient(server, timeout = 2)
        all_con = True
        for server, katcp_obj in servers.iteritems():
            try:
                logger.info('Check if {} is a cmc server.'.format(server))
                if not katcp_obj.rct.is_connected():
                    all_con = False
                    logger.fatal('{} is not a CMC server...'.format(server))
            except:
                all_con = False
                logger.fatal('{} is not alive...'.format(server))
        if not all_con:
            logger.fatal('CMC servers could not be contacted... closing connections.')  
            for server, katcp_obj in servers.iteritems():
                l = logging.getLogger(katcp_obj.io_manager.__module__)
                l.setLevel(logging.ERROR)
                katcp_obj.cleanup
            raise CMCNoConnection('CMC servers could not be contacted. Use -k option to specify cmc servers which are up, see help message.')
        self.conn_servers = servers
        return True

    def close_servers(self):
        if hasattr(self, 'conn_servers'):
            for server, katcp_obj in self.conn_servers.iteritems():
                self._release_cmc_lock(self.conn_servers[server])
                l = logging.getLogger(katcp_obj.io_manager.__module__)
                l.setLevel(logging.ERROR)
            try:
                for server, katcp_obj in self.conn_servers.iteritems():
                    katcp_obj.cleanup
            except NameError:
                pass

    def current_cmc_skarabs(self):
        """ Find skarabs currently managed by each cmc """
        if not hasattr(self, 'conn_servers'):
            try:
                self.connect_to_servers()
            except Exception as e:
                raise
        self.curr_cmc_skarabs = {}
        for server, katcp_obj in self.conn_servers.iteritems():
            logger.info('Retrieving list of skarabs from {}.'.format(server))
            try:
                reply,informs = katcp_obj.rct.req.resource_list(timeout=30)
                assert reply.reply_ok()
                inf_list = []
                for msg in informs:
                    inf_list.append(msg.arguments)
                self.curr_cmc_skarabs[server] = inf_list
            except AssertionError:
                logger.error('Could not retrieve list of skarabs: {}'.format(reply))
            except Exception as e:
                logger.error('KATCP error: {}'.format(e))

    def mark_skarabs(self, skarab_list):
        ''' Mark all skarabs on master up and standby on other CMC servers '''
        if not hasattr(self, 'curr_cmc_skarabs'):
            try:
                self.current_cmc_skarabs()
            except Exception as e:
                raise
        if not self.master:
            logger.error('Master CMC not specified.')
            raise MasterCMCUndefined('Master CMC not specified.')
        # Add skarabs to master if they are not present.
        added_skarabs = self.add_skarabs(skarab_list)
        # Refresh CMC skarab list
        if added_skarabs > 0:
            try:
                self.current_cmc_skarabs()
            except:
                raise
        # Mark skarabs standby on other CMC servers and check that they are not currently in an array
        error_standby = {}
        error_active = {}
        skarab_up_list = skarab_list[:]
        for server, katcp_obj in self.conn_servers.iteritems():
            error_standby[server] = 0
            error_active[server] = []
            if server != self.master:
                for skarab in skarab_list:
                    try:
                        skarab_info = [item for item in self.curr_cmc_skarabs[server] if item[0]==skarab][0]
                        # Check if target skarab is currently in an array
                        if len(skarab_info) > 2:
                            logger.warning('{} is currently in an active array on {}. Not marking standby'.format(skarab_info, server))
                            error_active[server].append(skarab_info[0])
                            skarab_up_list.remove(skarab)
                        elif skarab_info:
                            if not(self._mark_standby(katcp_obj, skarab)):
                                error_standby[server] += 1
                                skarab_up_list.remove(skarab)
                    except IndexError:
                        logger.debug('{} not present on {}'.format(skarab, server))

        for server, skarabs in error_active.iteritems():
            if skarabs:
                logger.error('Failed to mark SKARABs standby as they are in an active array on {}:\n{}'.format(server, skarabs))
        
        katcp_obj = self.conn_servers[self.master]
        error_up = 0
        skarabs_up = 0

        for skarab in skarab_up_list:
            if self._mark_up(katcp_obj, skarab):
                skarabs_up += 1
            else:
                error_up += 1

        for server,value in error_standby.iteritems():
            if value != 0:
                logger.warning('{} SKARABs could not be marked standby on {}. Check output above.'.format(value,server))
        if error_up != 0:
            logger.warning('{} SKARABs could not be marked up on {}. Check output above.'.format(error_up, self.master))
        if skarabs_up != 0:
            logger.info('{} SKARABs marked up on {}.'.format(skarabs_up, self.master))
    
    def check_cmc_consistency(self):
        ''' Check that no SKARABs are marked up on more than one server '''
        from collections import defaultdict
        if not hasattr(self, 'curr_cmc_skarabs'):
            try:
                self.current_cmc_skarabs()
            except:
                raise
        up_list = {}
        for server, skarabs in self.curr_cmc_skarabs.iteritems():
            up_list[server] = [skrb_info[0] for skrb_info in skarabs if skrb_info[1]=='up']
        seen = set()
        repeated = set()
        for server, skarabs in up_list.iteritems():
            for skarab in skarabs:
                if skarab in seen:
                    repeated.add(skarab)
                else:
                    seen.add(skarab)    
        duplicates = defaultdict(list)
        for skarab in repeated:
            for server, skarabs in up_list.iteritems():
                if skarab in skarabs:
                    duplicates[skarab].append(server)
        for skarab, servers in duplicates.iteritems():
            logger.warning('{} marked up on multiple CMC servers: {}'.format(skarab, servers))

    def add_skarabs(self, skarab_list):
        """ Add skarabs to master cmc server. """
        import re
        if not hasattr(self, 'curr_cmc_skarabs'):
            try:
                self.current_cmc_skarabs()
            except:
                raise
        if not self.master:
            logger.error('Master CMC not specified.')
            raise MasterCMCUndefined('Master CMC not specified.')
        skarabs = self.curr_cmc_skarabs[self.master]
        skarabs = [s[0].lower() for s in skarabs]
        not_present = list(set(skarab_list) - set(skarabs))
        added_skarabs = 0
        if not_present:
            if self._aquire_cmc_lock(self.conn_servers[self.master]):
                for skarab in not_present:
                    leaf_nr = None
                    for leaf, skarabs in self.skarab_map.iteritems():
                        if skarab in [i[0] for i in skarabs]:
                            leaf_nr = int(re.findall(r'\d+',leaf)[0])
                    if leaf_nr:
                        self._add_skarab(self.conn_servers[self.master], skarab, leaf_nr)
                        added_skarabs += 1
                    else:
                        logger.error('{} not found in the SKARAB map, update SKARAB map'.format(skarab))
                self._release_cmc_lock(self.conn_servers[self.master])
            else:
                logger.error('CMC lock could not be obtained on {}, CMC may be busy.'.format(self.conn_servers[self.master]))
        return added_skarabs

    def remove_skarabs(self, server, skarab_list):
        if not hasattr(self, 'conn_servers'):
            self.connect_to_servers()
        katcp_obj = self.conn_servers[server]
        for skarab in skarab_list:
            logger.info('Removing {} from {}'.format(skarab, katcp_obj.katcp_client))
            try:
                reply, informs = katcp_obj.rct.req.var_delete('resources:{}'.format(skarab))
                assert reply.reply_ok()
            except AssertionError:
                logger.error('Removing skarab not successful: {}'.format(reply.arguments[1:]))

    def _aquire_cmc_lock(self, katcp_obj):
        import time
        retry = 5
        while retry:
            try:
                reply, informs = katcp_obj.rct.req.var_set('locks', self.lock_entity, 'string', ':boards')
                assert reply.reply_ok()
                break
            except AssertionError:
                try:
                    reply, informs = katcp_obj.rct.req.var_show('locks')
                    assert reply.reply_ok()
                    locked_by = informs[0].arguments
                    if locked_by[0] == 'locks:boards':
                        if locked_by[1] == self.lock_entity:
                            logger.debug('{} already locked.'.format(katcp_obj.katcp_client))
                            break
                        else:
                            logger.debug('{} lock held by {}, retrying.'.format(katcp_obj.katcp_client, locked_by[1]))
                except (IndexError, AssertionError) as e:
                    logger.error('Strange behaviour during lock request on {}: {}, {}'.format(katcp_obj.katcp_client, reply, informs))
                retry -= 1
                time.sleep(2)

        if retry:
            logger.debug('Boards lock aquired on {}'.format(katcp_obj.katcp_client))
            self.locked[katcp_obj.katcp_client] = True
            return True
        else:
            return False

    def _release_cmc_lock(self, katcp_obj):
        try:
            reply, informs = katcp_obj.rct.req.var_show('locks')
            assert reply.reply_ok()
            try:
                locked_by = informs[0].arguments
                if locked_by[0] == 'locks:boards':
                    if locked_by[1] == self.lock_entity:
                        reply, informs = katcp_obj.rct.req.var_delete('locks:boards')
                        assert reply.reply_ok()
                        logger.debug('Boards lock released on {}'.format(katcp_obj.katcp_client))
                        self.locked[katcp_obj.katcp_client] = False
                    #else:
                    #    logger.fatal('{} lock held by {} while trying to delete {}. This should not happen, check lock logic.'.format(katcp_obj.katcp_client, locked_by[1], self.lock_entity))
            except IndexError:
                pass
        except AssertionError as e:
            logger.error('Strange behaviour during lock request on {}: {}, {}'.format(katcp_obj.katcp_client, reply, informs))

    def _add_skarab(self, katcp_obj, skarab, switch, mode='user'):
        ''' CMC lock must be obtained before using this method'''
        import time
        logger.info('Adding {} to {}'.format(skarab, katcp_obj.katcp_client))
        def var_set(field1, field2, field3, field4):
            try:
                reply, informs = katcp_obj.rct.req.var_set(field1, field2, field3, field4)
                assert reply.reply_ok()
            except AssertionError:
                logger.error('Adding skarab not successful:\n{}'.format(reply.arguments[1:]))
        try:
            ip_addr = self._getent(skarab).split()
            ip_addr = ip_addr[0]
            now = int(time.time())+1
            var_set('resources', 'skarab', 'string', ':{}:type'.format(skarab))
            var_set('resources', mode, 'string', ':{}:mode'.format(skarab))
            var_set('resources', switch, 'string', ':{}:switch'.format(skarab))
            var_set('resources', 'standby', 'string', ':{}:status'.format(skarab))
            var_set('resources', now, 'string', ':{}:when'.format(skarab))
            var_set('resources', ip_addr, 'string', ':{}:ip'.format(skarab))
        except AttributeError:
            logger.error('Adding skarab not successful: No IP entry found for {}'.format(skarab))

    def _mark_up(self, katcp_obj, skarab):
        try:
            reply, informs = katcp_obj.rct.req.resource_mark('{}'.format(skarab), 'up', timeout=30)
            assert reply.reply_ok()
            logger.info('Marked {} up on {}'.format(skarab, katcp_obj.katcp_client))
        except AssertionError:
            reason = reply.arguments[1:]
            if not(reason):
                logger.warning('Marking {} not successful, check logs in {}:/var/log/cmc.kcplog'
                                ''.format(skarab, katcp_obj.katcp_client))
                return False
            if reason[0].find('network') != -1:
                if self._mark_mode_auto(katcp_obj, skarab):
                    logger.warning('{} could not ping {}. Changing mode to auto, cmc-herder will mark to up when possible.'
                                  ''.format(katcp_obj.katcp_client, skarab))
                else:
                    logger.warning('Makring SKARAB not successful, {} could not ping {}.'
                                  ''.format(katcp_obj.katcp_client, skarab))
            elif reason[0].find('denied') != -1:
                logger.warning('Marking skarab not successful, {} marked standby in {} configuration.'
                              ''.format(skarab, katcp_obj.katcp_client))
            elif reason[0].find('unknown') != -1:
                logger.warning('Marking skarab not successful, {} not present on {}.'
                              ''.format(skarab, katcp_obj.katcp_client))
            else:
                logger.warning('Marking {} not successful on {}, check logs in /var/log/cmc.kcplog'.format(skarab, katcp_obj.katcp_client))
            return False
        except Exception as e:
            logger.error('Marking {} failed, could not contact SKARAB {}'.format(skarab, e))
            return False
        return True

    def _mark_mode_auto(self, katcp_obj, skarab):
        if self._aquire_cmc_lock(katcp_obj):
            logger.debug('Changing {} mode to auto on {}'.format(skarab, katcp_obj.katcp_client))
            try:
                reply, informs = katcp_obj.rct.req.var_delete('resources:{}:mode'.format(skarab))
                assert reply.reply_ok()
            except AssertionError:
                logger.error('Deleting skarab mode not successful:\n{}'.format(reply.arguments[1:]))
                self._release_cmc_lock(katcp_obj)
                return False
            try:
                reply, informs = katcp_obj.rct.req.var_set('resources', 'auto', 'string', ':{}:mode'.format(skarab))
                assert reply.reply_ok()
            except AssertionError:
                logger.error('Setting skarab mode not successful:\n{}'.format(reply.arguments[1:]))
                self._release_cmc_lock(katcp_obj)
                return False
            self._release_cmc_lock(katcp_obj)
            return True
        else:
            logger.error('CMC lock could not be obtained on {}, CMC may be busy.'.format(katcp_obj.katcp_client))
            return False

    def _mark_standby(self, katcp_obj, skarab):
        try:
            reply, informs = katcp_obj.rct.req.resource_mark('{}'.format(skarab), 'standby')
            assert reply.reply_ok()
            logger.info('Marked {} standby on {}'.format(skarab, katcp_obj.katcp_client))
        except AssertionError:
            if not(reason):
                logger.warning('Marking skarab not successful, check logs in /var/log/cmc.kcplog')
                return False
            if reason[0].find('network') != -1:
                logger.warning('Marking skarab not successful, {} could not ping {}.'
                              ''.format(katcp_obj.katcp_client, skarab))
            elif reason[0].find('denied') != -1:
                logger.warning('Marking skarab not successful, {} marked standby in {} configuration.'
                              ''.format(skarab, katcp_obj.katcp_client))
            elif reason[0].find('unknown') != -1:
                logger.warning('Marking skarab not successful, {} not present on {}.'
                              ''.format(skarab, katcp_obj.katcp_client))
            else:
                logger.warning('Marking skarab not successful, check logs in /var/log/cmc.kcplog')
            return False
        except Exception as e:
            logger.error('Marking {} failed, could not contact SKARAB.'.format(skarab))
            return False
        return True

    def _ping(self, host):
        import subprocess
        try:
            response = subprocess.check_output(
                ['ping', '-c', '1', host],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
        except subprocess.CalledProcessError:
            response = None
        return response

    def _getent(self, host):
        import subprocess
        try:
            response = subprocess.check_output(
                ['getent', 'hosts', host],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
        except subprocess.CalledProcessError:
            response = None
        return response

class UpdateSkarabMap:

    def __init__(self, skarab_map_fn = 'skarab_location_map.lst', switch_list = range(5,23), loglevel='INFO'):
        self.loglevel = loglevel
        self.skarab_map_fn = skarab_map_fn
        self.temp_fn = 'temp_skarab_map.txt'
        logger.debug('Using {} as filename to store SKARAB locations.'.format(self.skarab_map_fn))
        self.switch_list = switch_list
        logger.debug('Using leaf switches: {}'.format(self.switch_list))

    def _open_ssh(self):
        from switchcomms import SwitchComms
        switch_comms = SwitchComms(logger=logger)
        hosts = ['cbfsw-l{}.cbf.mkat.karoo.kat.ac.za'.format(switch) for switch in self.switch_list]
        ssh_list = switch_comms.open_connections(hosts)
        return ssh_list, switch_comms
    
    def _close_ssh(self, ssh_list, switch_comms):
        switch_comms.close_ssh(ssh_list)

    def _get_switch_arp(self, ssh_list, switch_comms):
        response = switch_comms.execute_commands(ssh_list, cmds = ['show ip arp'], timeout = 2)
        return response

    def _check_skarab_consistency(self, display_only=False):
        import json, re
        from collections import OrderedDict
        if display_only:
            filen = self.temp_fn
        else:
            filen = self.skarab_map_fn
        with open(filen) as fn:
            skarab_dict = json.load(fn)
        # Check if all skarab entries contains an IP address and a port
        problem_skarabs = 0
        for switch, skarabs_on_switch in skarab_dict.iteritems():
            rem_items = []
            for item in skarabs_on_switch:
                if item[1] == '':
                    logger.error('{} on {} not assigned an IP address, check manually.'.format(item[0], switch))
                    rem_items.append(item)
                elif item[2] == '':
                    logger.error('{} on {} not assigned a port, check manually.'.format(item[0], switch))
                    rem_items.append(item)
            if rem_items:
                # remove malformed items
                problem_skarabs += len(rem_items)
                skarab_dict[switch] = [i for i in skarabs_on_switch if i not in rem_items]
            

        # Splits key into text and number, converts number to int, uses that to sort and saves in an ordered dictionary
        # TODO: check ip address makes sense
        leafnum_toint = lambda k,v: [k, int(v)]
        skarab_dict = OrderedDict(sorted(skarab_dict.items(), key=lambda t: leafnum_toint(*re.match(r'([a-zA-Z-]+)(\d+)',t[0]).groups())))
        portnum_toint = lambda skrb,ip,port: [skrb, ip, int(port)]
        for switch, skarabs_on_switch in skarab_dict.iteritems():
            skarabs_on_switch = sorted(skarabs_on_switch, key = lambda t: int(t[2]))
            for item in skarabs_on_switch:
                logger.info('{} with IP {: <12} on {: <9}, port {}'.format(item[0], item[1], switch, item[2]))
        num_skarabs = 0
        for switch, skarabs_on_switch in skarab_dict.iteritems():
            logger.info('{: <9} hosts {: <2} SKARABs.'.format(switch,len(skarabs_on_switch))) 
            num_skarabs += len(skarabs_on_switch)
        logger.info('Total number of SKARABS in the system: {}'.format(num_skarabs))
        if problem_skarabs:
            logger.error('Found {} problematic SKARABs. Check output above.'.format(problem_skarabs))

    def update_skarab_map(self, display_only=False):
        import re, json
        from collections import defaultdict

        # Match mac address
        mac_pat = re.compile('^(06:50:02:)([0-9a-fA-F][0-9a-fA-F]:){2}(01)')
        # Match IP address
        ip_pat = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        # Match port number
        eth_pat = re.compile('^\d{1,2}\/\d{1,2}')
        skarab_dict = defaultdict(list)
        # Query switches more than once (not sure why, need to investigate)
        logger.info('Querying the following leaf switches for connected SKARABs:')
        ssh_list, switch_comms = self._open_ssh()
        error_msg = ''
        for i in range(3):
            arp_reply = self._get_switch_arp(ssh_list, switch_comms)
            for val in arp_reply:
                if val.find('ERROR') != -1:
                    error_msg = error_msg.join(val)
                else:
                    val = val.split('\n')
                    switch = val[-1].split(' ')[0]
                    for line in val:
                        line = line.split(' ')
                        mac = filter(mac_pat.match, line)
                        if mac:
                            mac = mac[0].split(':')
                            skarab_sn = 'skarab02{}{}-01'.format(mac[3],mac[4]).lower()
                            try:
                                ip = filter(ip_pat.match, line)[0]
                            except IndexError:
                                ip = ''
                            try:
                                port = filter(eth_pat.match, line)[0].split('/')[-1]
                            except IndexError:
                                port = ''
                            if switch in skarab_dict.keys():
                                if True in [x[0] == skarab_sn for x in skarab_dict[switch]]:
                                    pass
                                else:
                                    skarab_dict[switch].append([skarab_sn, ip, port])
                            else:
                                skarab_dict[switch].append([skarab_sn, ip, port])
        if error_msg:
            logger.error('Switch response error:\n{}'.format(val))
        self._close_ssh(ssh_list, switch_comms)
        if display_only:
            filen = self.temp_fn
        else:
            filen = self.skarab_map_fn
        with open(filen, 'w') as fn:
            json.dump(skarab_dict, fn)
        self._check_skarab_consistency(display_only = display_only)


def parse_arguments():
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
    desc = """
    """
    parser = ArgumentParser(description=desc, formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('-i', '--display_skarab_map', action='store_true', default=False,
            help='Display current state of all SKARABS')
    parser.add_argument('-m', '--master', type=str, default='', 
            help='CMC that will manage specified SKARABs, will be marked standby on all other CMCs.')
    parser.add_argument('-a', '--manage_per_leaf', type=int, nargs='+', action='store', choices=range(5,23),
            help='Command line space delimited list of leaf switches, specify only leaf number (5 .. 22). '
                 'All SKARABs to the leaf switch will be managed by CMC specified with the "master" option. '
                 'Note the SKARAB map must be up to date.', metavar='')
    parser.add_argument('-u', '--skarab_map', type=str, default='skarab_location_map.lst',
            help='Query switches and use LLDP responses to update map of SKARAB locations, note SKARABs'
                 'must have an IP address assigned. This map must be up to date if the manage skarabs '
                 'by leaf option is used.')
    #parser.add_argument('-u', '--skarab_map', type=str, nargs='?', const='skarab_location_map.lst',
    #        help='Query switches and use LLDP responses to update map of SKARAB locations, note SKARABs'
    #             'must have an IP address assigned. This map must be up to date if the manage skarabs '
    #             'by leaf option is used. File when option specified with no value: skarab_location_map.lst')
    parser.add_argument('-f', '--skarab_list', type=str, action='store', default='',
            help='File containing space delimited list of SKARABs to be managed by master CMC.')
    parser.add_argument('-d', '--dnsmasq', type=str, nargs='?', const='/var/lib/misc/dnsmasq.leases',
            help='Search for skarabs in specified leases file to be managed by master CMC.'
                 'File location when option specified with no value: /var/lib/misc/dnsmasq.leases')
    parser.add_argument('-k', '--katcp_servers', nargs = '+', type=str, default=['cmc1', 'cmc2', 'cmc3'],
            help='List of katcp servers, space separated.')
    parser.add_argument('-n', '--domain', type=str, default='cbf.mkat.karoo.kat.ac.za',
            help='Domain for katcp servers.')
    parser.add_argument('-s', '--use_skarab_map', action='store_true', default=False,
            help='Use current SKARAB map, do not query switches and update map.')
    parser.add_argument('-l', dest='loglevel', type=str, default='INFO',
                      help='Log level: DEBUG,INFO,WARNING,ERROR,FATAL.')
    return parser

def main():
    import sys, os, re, time, json

    parser = parse_arguments()
    args   = parser.parse_args()
    logger.setLevel(args.loglevel)

    if args.display_skarab_map:
        usm = UpdateSkarabMap(skarab_map_fn = args.skarab_map)
        usm.update_skarab_map(display_only = True)
        sys.exit()

    if args.skarab_map and not(args.use_skarab_map):
        usm = UpdateSkarabMap(skarab_map_fn = args.skarab_map)
        usm.update_skarab_map()
    else:
        args.skarab_map = 'skarab_location_map.lst'

    if (args.manage_per_leaf or args.skarab_list or args.dnsmasq) and not(args.master):
        parser.error('CMC master must be specified.')

    # Read skarab map
    if os.path.isfile(args.skarab_map):
        with open(args.skarab_map) as fn:
            skarab_map = json.load(fn)
    else:
        parser.error('SKARAB location map missing. Run script with skarab_map option.')

    skarab_list = []
    if args.manage_per_leaf:
        # Remove duplicates
        args.manage_per_leaf = list(set(args.manage_per_leaf))
        leafnum_toint = lambda k,v: (int(v))
        key_list = map(lambda t: [leafnum_toint(*re.match(r'([a-zA-Z-]+)(\d+)',t).groups()), t], skarab_map.keys())
        key_list = [x[1] for x in key_list if x[0] in args.manage_per_leaf]
        skarab_list = [skarab_map[key] for key in key_list]
        flatten = lambda l : [item for sublist in l for item in sublist]
        skarab_list = flatten(skarab_list)
        skarab_list = [str(column[0]) for column in skarab_list] 

    if args.dnsmasq:
        if os.path.isfile(args.dnsmasq):
            with open(args.dnsmasq) as f:
                for line in f:
                    if line.find('06:50:02') != -1:
                        skarab_list.append(line.split()[3])
        else:
            parser.error('Specified leases file does not exist.')
        if not(skarab_list):
            parser.error('No SKARABs found in the specified leases file.')

    if args.skarab_list:
        if os.path.isfile(args.skarab_list):
            with open(args.skarab_list) as f:
                for line in f:
                    line_skarabs = line.split(' ')
                    for item in line_skarabs:
                        item = item.lower()
                        if item.find("skarab") != -1:
                            item = item[:15]
                            skarab_list.append(item.rstrip())
        else:
            parser.error('Specified file does not exist.')

    # Remove duplicates
    skarab_list = list(set(skarab_list))
    # Convert all skrabas to lowercase
    skarab_list = [s.lower() for s in skarab_list]

    args.katcp_servers = [server + '.' + args.domain for server in args.katcp_servers]
    if args.master:
        manage_skarabs = ManageSkarabs(args.katcp_servers, skarab_map=skarab_map, master=args.master + '.' + args.domain)
    else:
        manage_skarabs = ManageSkarabs(args.katcp_servers, skarab_map=skarab_map)
    if skarab_list:
        try:
            manage_skarabs.mark_skarabs(skarab_list)
        except Exception as e:
            logger.error('{}'.format(e))

    manage_skarabs.check_cmc_consistency()
    #TODO: add remove duplicates
    manage_skarabs.close_servers()
  

if __name__ == '__main__':
    main()
    import sys
