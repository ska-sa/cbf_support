import socket
import pickle
import logging
import sys
import multiprocessing
import time
import sys
import curses
import datetime
import IPython

####### CONSTANTS ##########

HEADERSIZE = 10
IPV4 = socket.AF_INET
TCP = socket.SOCK_STREAM
PORT = 12345
IPADDRESS = 'dbelab04'
#IPADDRESS = 'cmc3.cbf.mkat.karoo.kat.ac.za'
# IPADDRESS = 'localhost'  # localhost or 127.0.0.1

# Setup the logger
loglevel = 'WARNING'
logger = logging.getLogger('mellanox_switch_comms')
level = logging.getLevelName(loglevel)
logger.setLevel(level)
fmt = '%(asctime)s %(levelname)s %(funcName)s: %(message)s'
#fmt = '%(asctime)s %(levelname)s %(funcName)s:%(lineno)d %(message)s'
#fmt = '%(asctime)s %(levelname)s: %(message)s %(threadName)s'
date_fmt = '%Y-%m-%d %H:%M:%S'
logging_format = logging.Formatter(fmt, date_fmt)
handler = logging.StreamHandler()
handler.setFormatter(logging_format)
handler.setLevel(level)
logger.addHandler(handler)

####### FUNCTIONS #########

def draw(stdscr, shared_dict):
    from decimal import Decimal

    def fexp(number):  # returns the order of magnitude of number
        (sign, digits, exponent) = Decimal(number).as_tuple()
        return len(digits) + exponent - 1

    def fman(number):  # returns number with decimal point after 1st digit
        return Decimal(number).scaleb(-fexp(number)).normalize()

    # Clear screMen
    stdscr.clear()
    lines = curses.LINES  # size of console screen HORI
    cols = curses.COLS  # size of console screen VERT
    matrix = shared_dict['t']
    m_rows = len(matrix[0])
    m_rows = m_rows + (m_rows / 2)  # m_rows = no of rows or lines for drawing matrix
    m_cols = len(matrix[0][0])  # m_cols = no of columns for drawing matrix
    # find max number size in matrix
    max_num = max([x for x in [j for i in matrix[0] for j in i] if isinstance(x, int)])
    colw = fexp(max_num) + 2
    if colw < 9: colw = 9
    blank_str = ' ' * colw
    # Initialise windows and colours
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_WHITE, -1)
    curses.init_pair(2, curses.COLOR_BLACK, -1)
    # curses.init_pair(3, curses.COLOR_BLUE, -1)
    # curses.init_pair(4, curses.COLOR_BLUE, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_YELLOW, -1)
    curses.init_pair(5, curses.COLOR_GREEN, -1)
    curses.init_pair(6, curses.COLOR_GREEN, -1)
    curses.init_pair(7, curses.COLOR_RED, -1)
    curses.init_pair(8, curses.COLOR_RED, -1)
    curses.init_pair(9, curses.COLOR_BLACK, curses.COLOR_YELLOW)  # colour scheme for discards
    curses.init_pair(10, curses.COLOR_BLACK, curses.COLOR_RED)  # colour scheme for errors
    curses.init_pair(11, curses.COLOR_BLACK, curses.COLOR_WHITE)  # colour scheme for switch status.
    curses.init_pair(12, curses.COLOR_BLACK, curses.COLOR_GREEN)  # for testing

    # curses.newpad(nlines, ncols)
    col_title = curses.newpad(1, m_cols * colw)
    row_title = curses.newpad(m_rows, colw)
    disp_wind = curses.newpad(m_rows, m_cols * colw)
    top_cornr = curses.newpad(1, colw)
    top_cornr.addstr(0, 0, 'Rates', curses.A_BOLD | curses.A_UNDERLINE)
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
    dwmincol = colw + 1
    dwmaxrow = lines - 1
    dwmaxcol = cols - 1
    dwrows = dwmaxrow - dwminrow
    dwcols = dwmaxcol - dwmincol
    # Column title display window
    ctminrow = 0
    ctmincol = colw + 1
    ctmaxrow = 0
    ctmaxcol = cols - 1
    # Row title display window
    rtminrow = 1
    rtmincol = 0
    rtmaxrow = lines - 1
    rtmaxcol = colw
    stdscr.nodelay(1)
    try:
        data_rdy = True
        blink = True
        ###pool = ThreadPool(processes=1)
        while True:
            if data_rdy:
                data_rdy = False
                ###thread_obj = pool.apply_async(get_discard, args=(switch_dict, ssh_list, matrix))
                blankc = 0
                reverse = False
                # for k, page in enumerate(matrix):
                #     if k == 0:
                for i, row in enumerate(matrix[12]):
                    if i == 0:  # row 0 or line 0
                        for j, val in enumerate(row):
                            if val == 0:
                                val = 'N/C'
                            if j == 0:
                                pass
                            else:
                                col_title.addstr(i, (j - 1) * colw, '{0:>{1}}'.format(val, colw),
                                                 curses.A_BOLD | curses.A_UNDERLINE)

                    else:
                        for j, val in enumerate(row):
                            if j == 0:  # for first title row in display
                                if val == 0:
                                    val = 'N/C'
                                col_pair = 1
                                if reverse: col_pair += 1
                                row_title.addstr(i + blankc - 1, 0, val, curses.color_pair(
                                    col_pair) | curses.A_BOLD)  # displays 1/1 out located in left-most column (column 0)

                                if (i - 1) % 2 == 1:  # all even numbers eg 2,4,6,8,...
                                    row_title.addstr(i + blankc - 1 + 1, 0, ' ')
                            else:  # for rows following first title row ^
                                width = colw - 2
                                if not val:
                                    val = 0
                                man = fman(val)
                                exp = fexp(val)
                                if exp < 3:
                                    col_pair = 1
                                    if reverse: col_pair += 1
                                    rate = 'Bs'
                                    val = '{0:>{1}} {2}'.format(int(val), width - 1, rate)
                                elif exp < 6:
                                    col_pair = 1
                                    if reverse: col_pair += 1
                                    rate = 'KB'
                                    man *= 10 ** (exp - 3)
                                    man = man.normalize()
                                    if width - 8 < 0:
                                        val = '{0:>{1}} {2}'.format(int(man), width - 1, rate)
                                    else:
                                        val = '{0:{1}.1f} {2}'.format(man, width - 1, rate)
                                elif exp < 9:
                                    col_pair = 3
                                    if reverse: col_pair += 1
                                    rate = 'MB'
                                    man *= 10 ** (exp - 6)
                                    man = man.normalize()
                                    if width - 8 < 0:
                                        val = '{0:>{1}} {2}'.format(int(man), width - 1, rate)
                                    else:
                                        val = '{0:{1}.1f} {2}'.format(man, width - 1, rate)
                                elif exp < 12:
                                    if man > 4.8:
                                        col_pair = 7
                                        if reverse: col_pair += 1
                                        col_title.addstr(0, (j - 1) * colw, '{0:>{1}}'.format(matrix[12][0][j], colw),
                                                         curses.color_pair(
                                                             col_pair) | curses.A_BOLD | curses.A_UNDERLINE)
                                        row_title.addstr(i + blankc - 1, 0, matrix[12][i][0],
                                                         curses.color_pair(col_pair) | curses.A_BOLD)
                                    else:
                                        col_pair = 5
                                        if reverse: col_pair += 1
                                    rate = 'GB'
                                    man *= 10 ** (exp - 9)
                                    man = man.normalize()
                                    val = '{0:{1}.1f} {2}'.format(man, width - 1, rate)
                                else:
                                    col_pair = 1
                                    rate = 'Bs'
                                    val = '{0:>{1}} {2}'.format(int(val), width - 1, rate)

                                disp_wind.addstr(i + blankc - 1, (j - 1) * colw, val,
                                                 curses.color_pair(col_pair))  # default colour scheme

                                if 0 < i < 37:  # ports 1/1 - 1/18
                                    if matrix[1][i][j] > 0:  # leaf errors, set backgrd colour for text red
                                        disp_wind.addstr(i + blankc - 1, (j - 1) * colw, val,
                                                         curses.color_pair(10))  # 10=RED for errors
                                        col_title.addstr(0, (j - 1) * colw, '{0:>{1}}'.format(matrix[0][0][j], colw),
                                                         curses.color_pair(10) | curses.A_BOLD | curses.A_UNDERLINE)
                                        row_title.addstr(i + blankc - 1, 0, matrix[12][i][0],
                                                         curses.color_pair(10) | curses.A_BOLD)
                                    if matrix[2][i][j] > 0:  # leaf discards, set backgrd colour for text yellow
                                        disp_wind.addstr(i + blankc - 1, (j - 1) * colw, val,
                                                         curses.color_pair(9))  # 9=YELLOW for discards
                                        col_title.addstr(0, (j - 1) * colw, '{0:>{1}}'.format(matrix[0][0][j], colw),
                                                         curses.color_pair(9) | curses.A_BOLD | curses.A_UNDERLINE)
                                        row_title.addstr(i + blankc - 1, 0, matrix[12][i][0],
                                                         curses.color_pair(9) | curses.A_BOLD)

                                if i in range(38, 73, 2):  # leaf ingress ports 1/19 - 1/36
                                    if matrix[1][i][j] > 0:  # leaf errors, set backgrd colour for text red
                                        disp_wind.addstr(i + blankc - 1, (j - 1) * colw, val,
                                                         curses.color_pair(10))  # 10=RED for errors
                                        col_title.addstr(0, (j - 1) * colw, '{0:>{1}}'.format(matrix[0][0][j], colw),
                                                         curses.color_pair(10) | curses.A_BOLD | curses.A_UNDERLINE)
                                        row_title.addstr(i + blankc - 1, 0, matrix[12][i][0],
                                                         curses.color_pair(10) | curses.A_BOLD)
                                    if matrix[2][i][j] > 0:  # spines discards, set backgrd colour for text yellow
                                        disp_wind.addstr(i + blankc - 1, (j - 1) * colw, val,
                                                         curses.color_pair(9))  # 9=YELLOW for discards
                                        col_title.addstr(0, (j - 1) * colw, '{0:>{1}}'.format(matrix[0][0][j], colw),
                                                         curses.color_pair(9) | curses.A_BOLD | curses.A_UNDERLINE)
                                        row_title.addstr(i + blankc - 1, 0, matrix[12][i][0],
                                                         curses.color_pair(9) | curses.A_BOLD)

                                if i in range(37, 72, 2):  # egress to spine ports 1/19 - 1/36
                                    if matrix[13][i][j] > 0:  # spines errors, set backgrd colour for text red
                                        disp_wind.addstr(i + blankc - 1, (j - 1) * colw, val,
                                                         curses.color_pair(10))  # 10=RED for errors
                                        col_title.addstr(0, (j - 1) * colw, '{0:>{1}}'.format(matrix[0][0][j], colw),
                                                         curses.color_pair(10) | curses.A_BOLD | curses.A_UNDERLINE)
                                        row_title.addstr(i + blankc - 1, 0, matrix[12][i][0],
                                                         curses.color_pair(10) | curses.A_BOLD)
                                    if matrix[14][i][j] > 0:  # spines discards, set backgrd colour for text yellow
                                        disp_wind.addstr(i + blankc - 1, (j - 1) * colw, val,
                                                         curses.color_pair(9))  # 9=YELLOW for discards
                                        col_title.addstr(0, (j - 1) * colw, '{0:>{1}}'.format(matrix[0][0][j], colw),
                                                         curses.color_pair(9) | curses.A_BOLD | curses.A_UNDERLINE)
                                        row_title.addstr(i + blankc - 1, 0, matrix[12][i][0],
                                                         curses.color_pair(9) | curses.A_BOLD)

                                if 0 < i < 37 or i in range(38, 73, 2):  # for ports 1/1 - 1/18 or ingress ports 1/19 - 1/36
                                    if time.time() - matrix[3][i][j] > 12:  # switch status, set colour scheme, no response in 12 sec
                                        disp_wind.addstr(i + blankc - 1, (j - 1) * colw, val, curses.color_pair(2)| curses.A_BOLD)  # 11=BLACK BOLD text for no switch reply
                                        # col_title.addstr(0, (j - 1) * colw, '{0:>{1}}'.format(matrix[0][0][j], colw),curses.color_pair(11) | curses.A_BOLD | curses.A_UNDERLINE)  # BLACK
                                        # row_title.addstr(i + blankc - 1, 0, matrix[12][i][0], curses.color_pair(11) | curses.A_BOLD)

                                if i in range(37, 72, 2):  # for egress to spine ports 1/19 - 1/36
                                    if time.time() - matrix[15][i][j] > 12:  # switch status, set colour scheme, no response in 12 sec
                                        disp_wind.addstr(i + blankc - 1, (j - 1) * colw, val, curses.color_pair(2) | curses.A_BOLD)  # 11=BLACK BOLD text for no switch reply
                                        # col_title.addstr(0, (j - 1) * colw, '{0:>{1}}'.format(matrix[0][0][j], colw), curses.color_pair(11) | curses.A_BOLD | curses.A_UNDERLINE)  # BLACK
                                        # row_title.addstr(i + blankc - 1, 0, matrix[12][i][0], curses.color_pair(11) | curses.A_BOLD)

                                if (i - 1) % 2 == 1:
                                    disp_wind.addstr(i + blankc - 1 + 1, (j - 1) * colw, ' ')
                        if (i - 1) % 2 == 1:
                            blankc += 1
                            reverse = False  # not(reverse)
                # prev_matrix = matrix
            else:
                char = stdscr.getch()
                if char == curses.ERR:
                    matrix = shared_dict['t']
                    data_rdy = True
                    # if blink:
                    #     top_cornr.addstr(0, 0, 'Rates', curses.A_BOLD | curses.A_UNDERLINE | curses.A_REVERSE)
                    # else:
                    #     top_cornr.addstr(0, 0, 'Rates', curses.A_BOLD | curses.A_UNDERLINE)
                    #     blink = not (blink)
                    if shared_dict['c']:
                        top_cornr.addstr(0, 0, 'Rates', curses.A_BOLD | curses.A_UNDERLINE | curses.A_REVERSE)
                    else:
                        top_cornr.addstr(0, 0, 'Rates', curses.A_BOLD | curses.A_UNDERLINE)
                else:
                    if char == curses.KEY_LEFT:
                        if dmincol > colw:
                            dmincol -= colw
                        else:
                            dmincol = 0
                    elif char == curses.KEY_RIGHT:
                        if dmincol < (m_cols - 2) * colw - dwcols:
                            dmincol += colw
                        else:
                            dmincol = (m_cols - 1) * colw - dwcols
                    elif char == curses.KEY_UP:
                        if dminrow > 0:
                            dminrow -= 1
                        else:
                            dminrow = 0
                    elif char == curses.KEY_DOWN:
                        if dminrow < m_rows - dwrows - 2:
                            dminrow += 1
                        else:
                            dminrow = m_rows - dwrows - 2
                    # elif char == 'c' or 'C':
                    #     cmd = 'clear counters all'
                    #     dummy = run_threaded_cmd(ssh_list, cmd, enable=True)

            # Shift titles with text
            cmincol = dmincol
            rminrow = dminrow
            disp_wind.refresh(dminrow, dmincol, dwminrow, dwmincol, dwmaxrow, dwmaxcol)
            col_title.refresh(cminrow, cmincol, ctminrow, ctmincol, ctmaxrow, ctmaxcol)
            row_title.refresh(rminrow, rmincol, rtminrow, rtmincol, rtmaxrow, rtmaxcol)
            top_cornr.refresh(0, 0, 0, 0, 1, colw - 1)
    except KeyboardInterrupt:
        pass

def comms(shared_dict):
    try:
        s = socket.socket(IPV4, TCP)  # create socket object
        print 'Connecting to server...'
        s.connect((IPADDRESS, PORT))  # waits here and attempt connection to server
        print 'Connection established. Receiving data...'
        while True:
            full_msg = b''  # create empty variable
            new_msg = True  # set new_msg flag
            while True:
                msg = s.recv(16)  # buffer size 16 bytes for incoming message
                if new_msg:
                    msg_len = int(msg[:HEADERSIZE])  # convert value in HEADER(expected message length) to int
                    new_msg = False  # clear new_msg flag

                full_msg += msg  # append messages

                if len(full_msg) - HEADERSIZE == msg_len:  # execute when complete message is received based on size indicated in HEADER
                    msg_size = str(sys.getsizeof(full_msg))
                    matrix_received = pickle.loads(full_msg[HEADERSIZE:])  # unpickle data
                    matrix_size = str(sys.getsizeof(matrix_received))
                    shared_dict['t'] = matrix_received
                    shared_dict['c'] = not shared_dict['c']
                    logger.info('Full message received: %i Bytes.', int(msg_size))
                    # logger.info('Matrix size: %s bytes.', matrix_size)
                    # logger.info('%s       %s       %s', matrix_received[0][0][0], matrix_received[0][0][1],matrix_received[0][0][2])
                    # logger.info('%s %s     %s', matrix_received[0][1][0], matrix_received[0][1][1],matrix_received[0][1][2])
                    # print 'New message received.'
                    # print 'Size = ', msg_size
                    new_msg = True  # set new_msg flag
                    full_msg = b""  # clear/empty message
    except socket.error as e:
        #print "Socket Error: %s" % e
        logger.info("Socket Error: %s" % e)
    except KeyboardInterrupt as e:
        #print("KeyboardInterrupt has been caught.")
        logger.info("Keyboard Error: %s" % e)
    except Exception as e:
        #print "Generic error: %s" % e
        logger.info("Generic Error: %s" % e)
    finally:
        s.close()
        shared_dict['terminate'] = True
        logger.info('Socket closed')
        logger.info('Comms thread has ended.')

def display(shared_dict):
    while shared_dict['terminate'] == False:
        time.sleep(3)
        x = shared_dict['c']
        y = shared_dict['t']
        # print len(matrix)
        #print 'shared_dict c: {}'.format(x)
        print 'shared_dict t: {}'.format(y)
    logger.info('Display thread has ended.')



####### MAIN #######

if __name__ == '__main__':

    try:
        manager = multiprocessing.Manager()

        default_data = 'default'

        shared_dict = manager.dict({'t': default_data, 'c': False, 'terminate': False})

        p1 = multiprocessing.Process(target=comms, args=(shared_dict,))
        p1.start()  # start comms function
        while len(shared_dict['t']) != 16:  # wait until matrix message is received
            time.sleep(0.5)
        # p2 = multiprocessing.Process(target=display, args=(shared_dict,))
        # p2.start()
        p3 = multiprocessing.Process(target=curses.wrapper, args=(draw, shared_dict))
        p3.start()

        while shared_dict['terminate'] == False:
            pass

        p1.join()
        p3.join()
        logger.info('Server has ended.')

    except Exception as e:
        logger.info("Error: %s" % e)
        logger.info('Server has ended.')

####### END OF MAIN #######



    #
