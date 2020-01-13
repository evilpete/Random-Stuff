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
# import time
import readline
# import rlcompleter
# from rflib import *
import rflib
import bitstring
readline.parse_and_bind("tab: complete")
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

cmd = 'Med'
DRATE = 3015
cmd_repeat = 50
rf_freq = 302500000
TX_Power = 96 # 192     # Default
chan_bw = 640000
Sec_Code = '1001'

fan_cmd = {
    'Hi':  "100000",
    'Med': "010000",
    'Low': "001000",
    'Xxx': "000100",
    'Off': "000010",
    'Lit': "000001",
    'End': "000000",
}


prefix = '0' * 14


if __name__ == "__main__":

    # Command Pkt (13bits):
    # 01 + 4bit Sec_Code + 0 + 6bit Command Code
    cmd_code = ''.join(['01', Sec_Code, '0', fan_cmd[cmd]])


    # Convert the data to a PWM key by looping over the
    # data string and replacing a 1 with 100 and a 0
    # with 110
    pwm_key = ''.join(['011' if b == '1' else '001' for b in cmd_code])

    if verbose:
        print('prefix:', prefix)
        print('command Code:', cmd_code)
        print("pwm_key", len(pwm_key), pwm_key)

    # Join the prefix and the data for the full pwm key
    full_pwm = '{}{}{}'.format(prefix * 2, pwm_key, prefix) * 3

    if verbose > 1:
        print('Sending full PWM key: {}'.format(full_pwm))
        print("full_pwm", len(full_pwm), full_pwm)

    # Convert the data to hex
    rf_data = bitstring.BitArray(bin=full_pwm).tobytes()

    # Start up RfCat
    d = rflib.RfCat()

    # Set Modulation. We using On-Off Keying here
    d.setMdmModulation(rflib.MOD_ASK_OOK)

    # Configure the radio
    d.makePktFLEN(len(rf_data)) # Set the RFData packet length
    d.setMdmDRate(DRATE)         # Set the Baud Rate
    d.setMdmSyncMode(0)         # Disable preamble
    d.setFreq(rf_freq)        # Set the frequency

    # d.setMaxPower()
    if TX_Power:
        d.setPower(TX_Power)

    if chan_bw:
        d.setMdmChanBW(chan_bw)

    if verbose:
        bw = d.getMdmChanBW()
        dr = d.getMdmDRate()
        f1 = d.getFreq()
        print("DRate:", dr, bw)
        print("Freq:", f1[0])


    # print("FreqReg:", d.radiocfg.freq2, d.radiocfg.freq1, d.radiocfg.freq2)

    if verbose:
        print("Repeat:", cmd_repeat)

    for i in range(0, 20):
    # Send the data string a few times

        d.RFxmit(rf_data, repeat=cmd_repeat)
        # time.sleep(.25)


    d.setModeIDLE()
