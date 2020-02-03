#!/usr/bin/python



"""
    Send Ceiling Fan RF Remote Commands
"""

#
# Emulates RF from Fan-11T Ceiling Fans Remote
# Used in products by Hampton Bay, Harbor breeze and others
#
# Utilizing the HT12E RF encoder
#
# FccID : L3HFAN11T
# https://www.fcc.gov/oet/ea/fccid
#
# See https://www.holtek.com/documents/10179/116711/2_12ev120.pdf
#
# Requires a YardStick One USB Device to Funtion
#    https://greatscottgadgets.com/yardstickone/

# pylint: disable=invalid-name


from __future__ import print_function

# import sys
import time
# import readline
import signal
import argparse
import atexit
# import rlcompleter
# from rflib import *
import rflib
import bitstring
# readline.parse_and_bind("tab: complete")
# import pprint

__author__ = "Peter Shipley"

verbose = 0

#
# baud is 1000 but we use 3k to emulate PWM
# freq is officially 303.9MHz  but 302.5MHz works better
# chan_bw : channel bandwidth (optional)
# TX_Power : Transmit power (optional)
#
# Sec_Code is the dip switch settings for the remote

DRATE = 3015
cmd_repeat = 3
rf_freq = 302400000
TX_Power = 192     # Default 96
chan_bw = 1100000 # 940000
Sec_Code = '1001'

fan_cmd = {
    'high':  "100000",
    'med': "010000",
    'low': "001000",
    # 'Xxx': "000100",
    'off': "000010",
    'lit': "000001",
    '# END': "000000",
}


prefix = '0' * 33

d = None

def handler(signum, _frame):
    """ stop rfcat device before exit """
    # pylint: disable=global-statement
    global d
    print('Signal handler called with signal', signum)
    if d is not None:
        # print('sig_handler setModeIDLE')
        d.setModeIDLE()
        d = None
    exit(0)


@atexit.register
def onexit():
    """ stop rfcat device before exit """
    # pylint: disable=global-statement
    global d
    # print("onexit")
    if d is not None:
        # print "onexit setModeIDLE"
        d.setModeIDLE()
        d = None

# atexit.register(onexit)

for _sig in [signal.SIGINT, signal.SIGTERM, signal.SIGQUIT]:
    signal.signal(_sig, handler)

def configure_RfCat(rf_debug=False):
    """
	create Rflib obj
	Configure RfCat device
	returns Rflib obj
    """

    # Start up RfCat
    c = rflib.RfCat(debug=rf_debug)
    c.RESET()

    # Set Modulation. We using On-Off Keying here
    c.setMdmModulation(rflib.MOD_ASK_OOK)

    # Configure the radio
    c.makePktFLEN(230) # Set the RFData packet length
    c.setMdmDRate(DRATE)         # Set the Baud Rate
    c.setMdmSyncMode(0)         # Disable preamble
    c.setMdmSyncWord(0x000)
    c.setFreq(rf_freq)        # Set the frequency
    c.setEnableMdmManchester(0)

    # c.setMaxPower()
    if TX_Power:
        c.setPower(TX_Power)

    if chan_bw:
        c.setMdmChanBW(chan_bw)

    if verbose:
        bw = c.getMdmChanBW()
        dr = c.getMdmDRate()
        f1 = c.getFreq()
        print("DRate:", dr, bw)
        print("Freq:", f1[0])

    return c

def build_cmd_str(keycode, commanmd):

    # Command Pkt (13bits):
    # 01 + 4bit Sec_Code + 0 + 6bit Command Code
    cmd_code = ''.join(['01', keycode, '0', fan_cmd[commanmd]])
    end_code = ''.join(['01', keycode, '0', "000000"])

    # Convert the data to a PWM by looping over the
    # data string and replacing a 1 with 100 and a 0
    # with 110
    pwm_key = ''.join(['011' if b == '1' else '001' for b in cmd_code])
    pwm_end = ''.join(['011' if b == '1' else '001' for b in end_code])

    if verbose:
        print('prefix:', prefix)
        print('command Code:', cmd_code)
        print("pwm_key", len(pwm_key), pwm_key)

    # Join the prefix and the data for the full pwm key
    # cmd_pwm = '{}{}'.format(prefix, pwm_key) * 4
    # end_pwm= '{}{}'.format(prefix, pwm_end) * 2
    #
    # if verbose > 1:
    #     print("cmd_pwm", len(cmd_pwm), cmd_pwm)
    #     print("end_pwm", len(end_pwm), end_pwm)
    #
    # full_pwm = cmd_pwm + end_pwm

    full_pwm = '{}{}'.format(prefix, pwm_key) * 4 + '{}{}'.format(prefix, pwm_end) * 2

    if verbose > 1:
        print('full_pwm', full_pwm)


    # Convert the ascii data to binary bits
    # rf_bits = bitstring.BitArray(bin=full_pwm).tobytes()

    return bitstring.BitArray(bin=full_pwm).tobytes()

def parse_args():

    parser = argparse.ArgumentParser(description='send command to Fan')
    parser.add_argument('-v', '--verbose',
                        help='Increase debug verbosity', action='count')
    parser.add_argument('-k', '--key',
                        help='4bit dip-switch code from remote',
                        action='store', default=None)
    parser.add_argument('-r', '--repeat',
                        help='number of times to repeat command',
                        action='store', default=None)
    parser.add_argument('-c', '--command',
                        help='command',
                        action='store', default=None)

    (arg, argv) = parser.parse_known_args()

    if argv and not arg.command:
        arg.command = argv[0]

    return arg

#
if __name__ == "__main__":

    args = parse_args()

    if args.verbose:
        verbose = args.verbose

    if args.key:
        Sec_Code = args.key

    cmd = args.command.lower()

    if cmd not in fan_cmd:
        print("invalid commanmd")
        print("Valid command list", " ".join(fan_cmd))
        exit(0)


    if verbose:
        print("command =", cmd)

    rf_data = build_cmd_str(Sec_Code, cmd)


    d = configure_RfCat()
    # print("FreqReg:", d.radiocfg.freq2, d.radiocfg.freq1, d.radiocfg.freq2)

    if verbose:
        print("Repeat:", cmd_repeat)

    # Send the data string a few times
    # for f in 302400000, 302500000, 302600000, 302700000:
    # d.setFreq(f)        # Set the frequency
    for i in range(0, cmd_repeat):
        d.RFxmit(rf_data, repeat=cmd_repeat)
        time.sleep(.05)


    if verbose > 1:
        rconf = d.reprRadioConfig()
        print("reprRadioConfig:", rconf)

    d.setModeIDLE()
    d = None
