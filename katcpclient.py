import logging
from katcp import resource_client, ioloop_manager

LOGGER = logging.getLogger(__name__)
Formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(module)s - '
                              '%(pathname)s : %(lineno)d - %(message)s')
Handler = logging.FileHandler('%s.log' % (__name__))
Handler.setFormatter(Formatter)
LOGGER.addHandler(Handler)



class KATCPClient():
    def __init__(self, katcp_client=None, katcp_port=7147, timeout=30):
        self.katcp_client = katcp_client
        self.prim_port = str(katcp_port)
        self._katcp_rct = None
        self._katcp_rct_sensor = None
        self._rct = None
        self.katcp_array_port = None
        self.katcp_sensor_port = None
        self.timeout=timeout

    @property
    def rct(self):
        if self._rct is not None:
            return self._rct
        else:
            self.io_manager = ioloop_manager.IOLoopManager()
            self.io_wrapper = resource_client.IOLoopThreadWrapper(
                self.io_manager.get_ioloop())
            self.io_wrapper.default_timeout = self.timeout
            self.io_manager.start()
            self.rc = resource_client.KATCPClientResource(
                dict(name='{}'.format(self.katcp_client),
                     address=('{}'.format(self.katcp_client),
                              self.prim_port),
                     controlled=True))
            self.rc.set_ioloop(self.io_manager.get_ioloop())
            self._rct = (resource_client.ThreadSafeKATCPClientResourceWrapper(self.rc,
                                                                              self.io_wrapper))
            self._rct.start()
            try:
                self._rct.until_synced(timeout=self.timeout)
            except TimeoutError:
                self._rct.stop()
        return self._rct

    @property
    def cleanup(self):
        try:
            self.io_manager.stop()
        except AttributeError:
            print('io_manager not present.')
        #try:
        #    self._rct.stop()
        #except AttributeError:
        #    print('_rct not present.')


