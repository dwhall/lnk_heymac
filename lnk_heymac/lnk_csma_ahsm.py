"""
Copyright 2019 Dean Hall.  See LICENSE for details.

Data Link Layer (LNK) state machine for Carrier-Sense Multiple Access (CSMA)
radio operations using Heymac frame protocol.
- listens for beacons and maintains a neighbors list with link stats
- periodically transmits a beacon frame
"""


import logging

import farc
import phy_sx127x

from . import lnk_data
from . import lnk_frame
from . import lnk_heymac_cmd
from . import lnk_heymac_cmd_asoc


class LnkHeymac(object):
    """Heymac link layer (LNK) protocol values."""
    # The Beacon Period.
    # The number of seconds between each emission of a beacon.
    # This value also affects the time a node spends lurking.
    BCN_PRD = 32

    # Link addresses are 8 octets in size
    # Heymac uses its long-address mode to convey a link address
    LNK_ADDR_SZ = 8

    # Link layer node capabilities (16 bit field).
    # These are bit flags used in the beacon's capabilities field.
    LNK_CAP_PWR = 0x0001        # Node has surplus power
    LNK_CAP_RXCONT = 0x0002     # Node is able to listen continuously
    LNK_CAP_CRYPTO = 0          # Node is capable of cryptographic routines
    # LNK_CAP_ROOT # No, this is net layer cap
    # LNK_CAP_NVSTO # Node has non-volatile storage (KBs? MBs? GBs?)

    # The number of seconds between each link update period in _linking()
    _LNK_UPDT_PRD = 4

    # The LoRa Sync Word is a SX127x register setting
    # that lets the hardware discriminate for frames
    # that have like Sync Words.
    # This value differs from power-up and LoRaWAN values,
    # but is otherwise an arbitrary choice: ASCII 'H'
    _HEYMAC_SYNC_WORD = 0x48

    # PHY settings
    _PHY_STNGS_DFLT = (
        ("FLD_RDO_LORA_MODE", 1),
        ("FLD_RDO_FREQ", 432_550_000),
        ("FLD_RDO_MAX_PWR", 7),
        ("FLD_RDO_PA_BOOST", 1),
        ("FLD_LORA_IMPLCT_HDR_MODE", 0),
        ("FLD_LORA_CR", 2),     # phy_sx127x.PhySX127x.STNG_LORA_CR_4TO6
        ("FLD_LORA_BW", 8),     # phy_sx127x.PhySX127x.STNG_LORA_BW_250K
        ("FLD_LORA_SF", 7),     # phy_sx127x.PhySX127x.STNG_LORA_SF_128_CPS
        ("FLD_LORA_CRC_EN", 1),
        ("FLD_LORA_SYNC_WORD", _HEYMAC_SYNC_WORD),
    )
    _PHY_STNGS_RX = (("FLD_RDO_FREQ", 432_550_000),)
    _PHY_STNGS_TX = (("FLD_RDO_FREQ", 432_550_000),)


class LnkHeymacCsmaAhsm(LnkHeymac, farc.Ahsm):
    """The link layer (LNK) state machine.

    Automates beaconing and frame processing.
    """
    def __init__(self, lnk_addr, station_id):
        """Class intialization"""
        super().__init__()

        # Instantiate the lower layer
        self.phy_ahsm = phy_sx127x.PhySX127xAhsm(True)
        self.phy_ahsm.set_dflt_stngs(LnkHeymac._PHY_STNGS_DFLT)
        self.phy_ahsm.set_dflt_rx_clbk(self._phy_rx_clbk)

        # TODO: these go in lnk data?
        assert type(lnk_addr) is bytes
        assert len(lnk_addr) is LnkHeymac.LNK_ADDR_SZ
        self._lnk_addr = lnk_addr
        self._station_id = station_id   # UNUSED

        self._lnk_data = lnk_data.LnkData(lnk_addr)

        # Init neighbor dialog state machine container
        self._ngbr_dlg_sm = {}

        # Init next-layer-higher dialog callback container
        self._nlh_dlg_clbk = {}


    def start_cmd_dlg(self, cmd_id, ngbr_lnk_addr, nlh_clbk, *args):
        """Starts a command dialog sequence.

        Starts the *DlgInitiatorAhsm with the given args and performs
        the specific command's dialog sequence.
        Calls the callback with results.
        This method is intended to be called by the next layer higher;
        so the callback calls into that layer.
        """
        cmd_dlg_cls = _CMD_DLG_INITR_SM_CLASSES[cmd_id]
        cmd_dlg_sm = cmd_dlg_cls(ngbr_lnk_addr, *args)
        priority = self.priority + len(self._ngbr_dlg)
        cmd_dlg_sm.start(priority)
        self._ngbr_dlg_sm[ngbr_lnk_addr] = cmd_dlg_sm
        self._nlh_dlg_clbk[ngbr_lnk_addr] = nlh_clbk


    def start_stack(self, ahsm_prio, delta_prio=10):
        """Starts this layer of the network stack.

        This layer must start the lower layer,
        giving it a higher priority (lower number)
        and then starts this layer's state machine.
        """
        assert delta_prio > 0, \
            "Lower layer must have higher priority (lower number)"
        assert ahsm_prio - delta_prio > 0, "Priorty must not go below zero"
        self.phy_ahsm.start_stack(ahsm_prio - delta_prio)
        self.start(ahsm_prio)


# State machine


    @farc.Hsm.state
    def _initial(self, event):
        """PseudoState: _initial

        State machine framework initialization
        """
        # Self-signaling
        farc.Signal.register("_ALWAYS")
        farc.Signal.register("_LNK_RXD_FROM_PHY")
        farc.Signal.register("_LNK_FRAME")

        # Self-signaling events
        self._evt_always = farc.Event(farc.Signal._ALWAYS, None)

        # Timer events
        self._bcn_evt = farc.TimeEvent("_LNK_BCN_TMOUT")
        self._tm_evt = farc.TimeEvent("_LNK_TMOUT")

        return self.tran(self._initializing)


    @farc.Hsm.state
    def _initializing(self, event):
        """State: _initializing

        Application initialization.
        Initializes LNK data and the pkt queue.
        Always transitions to the _lurking state.
        """
        sig = event.signal
        if sig == farc.Signal.ENTRY:
            logging.debug("LNK._initializing")

            # Data Link Layer data
            # self._lnk_data = lnk_csma_data.LnkData()

            # Transmit queue
            self.mac_txq = []

            self.post_fifo(self._evt_always)
            return self.handled(event)

        elif sig == farc.Signal._ALWAYS:
            return self.tran(self._lurking)

        elif sig == farc.Signal.EXIT:
            return self.handled(event)

        return self.super(self.top)


    @farc.Hsm.state
    def _lurking(self, event):
        """State: _lurking

        Waits for a fixed period with the receiver enabled,
        processes any received frames, and then
        transitions to the _beaconing state.
        """
        sig = event.signal
        if sig == farc.Signal.ENTRY:
            logging.debug("LNK._lurking")
            self._bcn_evt.post_in(self, 2 * LnkHeymac.BCN_PRD)
            return self.handled(event)

        elif sig == farc.Signal._LNK_BCN_TMOUT:
            return self.tran(self._beaconing)

        elif sig == farc.Signal._LNK_RXD_FROM_PHY:
            self._on_rxd_from_phy(event.value)
            return self.handled(event)

        elif sig == farc.Signal.EXIT:
            self._bcn_evt.disarm()
            return self.handled(event)

        return self.super(self.top)


    @farc.Hsm.state
    def _beaconing(self, event):
        """State: _lurking:_beaconing

        Periodically transmits a beacon.
        """
        sig = event.signal
        if sig == farc.Signal.ENTRY:
            logging.debug("LNK._beaconing")
            self._bcn_evt.post_every(self, LnkHeymac.BCN_PRD)
            self._post_bcn()
            return self.handled(event)

        elif sig == farc.Signal._LNK_BCN_TMOUT:
            logging.debug("LNK._beaconing@BCN_TMOUT")
            self._post_bcn()
            return self.handled(event)

        elif sig == farc.Signal._LNK_RXD_FROM_PHY:
            self._on_rxd_from_phy(event.value)
            if self._lnk_data.ngbr_hears_me():
                return self.tran(self._linking)
            return self.handled(event)

        elif sig == farc.Signal.EXIT:
            self._bcn_evt.disarm()
            return self.handled(event)

        return self.super(self._lurking)


    @farc.Hsm.state
    def _linking(self, event):
        """State: _lurking:_beaconing:_linking

        Indicates at least one neighbor has this node in its neighbor's list.
        This state starts a periodic timer used to perform updates
        on the link data (such as prune the neighbor list).
        """
        sig = event.signal
        if sig == farc.Signal.ENTRY:
            logging.debug("LNK._linking")
            self._tm_evt.post_every(self, LnkHeymac._LNK_UPDT_PRD)
            return self.handled(event)

        elif sig == farc.Signal._LNK_TMOUT:
            self._lnk_data.update()
            if not self._lnk_data.ngbr_hears_me():
                return self.tran(self._beaconing)
            return self.handled(event)

        elif sig == farc.Signal.EXIT:
            self._tm_evt.disarm()
            return self.handled(event)

        return self.super(self._beaconing)


# Private


    # Command dialog initiator state machine class lookup table
    _CMD_DLG_INITR_SM_CLASSES = {
        lnk_heymac_cmd_asoc.HeymacCmdAsoc.CMD_ID:
            lnk_heymac_cmd_asoc.HeymacCmdAsocDlgInitiatorAhsm,
    }

    # Command dialog responder state machine class lookup table
    _CMD_DLG_RSPDR_SM_CLASSES = {
        lnk_heymac_cmd_asoc.HeymacCmdAsoc.CMD_ID:
            lnk_heymac_cmd_asoc.HeymacCmdAsocDlgResponderAhsm,
    }


    def _on_rxd_from_phy(self, frame):
        """Processes a frame received from the PHY."""
        assert type(frame) is lnk_frame.HeymacFrame

        # Attach the Heymac command, if present
        try:
            cmd = lnk_heymac_cmd.HeymacCmd.parse(
                frame.get_field(lnk_frame.HeymacFrame.FLD_PAYLD))
        except lnk_heymac_cmd.HeymacCmdError:
            cmd = None
        frame.cmd = cmd

        # Process the frame for link data, etc.
        self._lnk_data.process_frame(frame)

        # If the frame is a multi-hop Heymac command
        if frame.cmd and frame.is_mhop():
            hops = frame.get_field(lnk_frame.HeymacFrame.FLD_HOPS)
            if hops > 1:
                # Update the hops and re-transmitter fields
                frame.set_field(lnk_frame.HeymacFrame.FLD_HOPS, hops - 1)
                frame.set_field(lnk_frame.HeymacFrame.FLD_TADDR,
                                self._lnk_addr)
                # Post the frame to PHY for transmission
                self._post_frm(frame)

        # If the frame is a Heymac command meant for this node
        if frame.cmd and frame.is_meant_for(self._lnk_addr):
            self._process_cmd(frame)

        # TODO: See if the NET layer wants to process the frame


    def _phy_rx_clbk(self, rx_time, rx_bytes, rx_rssi, rx_snr):
        """A method given to the PHY layer as a callback.

        The PHY calls this method with these arguments
        when it receives a frame with no errors.
        This method collects the arguments in a container
        and posts an event to this state machine.
        """
        # Parse the bytes into a frame
        # and store reception meta-data
        try:
            frame = lnk_frame.HeymacFrame.parse(rx_bytes)
            frame.rx_meta = (rx_time, rx_rssi, rx_snr)
        except lnk_frame.HeymacFrameError:
            logging.info("LNK:rxd frame is not valid Heymac\n\t{}"
                         .format(rx_bytes))
            # TODO: lnk stats incr rxd frame is not Heymac
            return

        # The frame is valid, post it to the state machine
        self.post_fifo(farc.Event(farc.Signal._LNK_RXD_FROM_PHY, frame))


    def _post_bcn(self,):
        """Builds a Heymac CsmaBeacon and posts it to the PHY for transmit."""
        bcn = lnk_heymac_cmd.HeymacCmdCsmaBcn(
            # TODO: Fill with real data
            FLD_CAPS=LnkHeymac.LNK_CAP_RXCONT,
            FLD_STATUS=0,
            FLD_NETS=(),
            FLD_NGBRS=self._lnk_data.get_ngbrs_lnk_addrs())
        frame = lnk_frame.HeymacFrame(
            lnk_frame.HeymacFrame.PID_IDENT_HEYMAC
            | lnk_frame.HeymacFrame.PID_TYPE_CSMA,
            lnk_frame.HeymacFrame.FCTL_L
            | lnk_frame.HeymacFrame.FCTL_S)
        frame.set_field(lnk_frame.HeymacFrame.FLD_SADDR, self._lnk_addr)
        frame.set_field(lnk_frame.HeymacFrame.FLD_PAYLD, bytes(bcn))
        self.phy_ahsm.post_tx_action(
            self.phy_ahsm.TM_NOW,
            LnkHeymac._PHY_STNGS_TX,
            bytes(frame))


    def _post_frm(self, frame):
        """Posts the frame to the PHY for transmit."""
        assert type(frame) is lnk_frame.HeymacFrame
        self.phy_ahsm.post_tx_action(
            self.phy_ahsm.TM_NOW,
            LnkHeymac._PHY_STNGS_TX,
            bytes(frame))


    def _process_cmd(self, frame):
        """Processes the Heymac command in the given frame."""
        print("DWH: _process_cmd")
        if type(frame.cmd) is lnk_heymac_cmd.HeymacCmdCsmaBcn:
            # TODO: join any unknown nets
            pass

        # If the received command involves a dialog
        elif frame.cmd.CMD_ID in _CMD_DLG_RSPDR_SM_CLASSES:
            print("DWH: HeymacCmdAsoc")
            # Create a dialog with the sender if one doesn't exist
            sender = frame.get_sender()
            if sender not in self._ngbr_dlg:
                rspdr_cls = _CMD_DLG_RSPDR_SM_CLASSES[frame.cmd.CMD_ID]
                self._ngbr_dlg[sender] = rspdr_cls()
                priority = self.priority + len(self._ngbr_dlg)
                self._ngbr_dlg[sender].start(priority)

            # Dispatch the frame event to the dialog state machine
            evt = farc.Event(farc.Signal._LNK_FRAME, frame)
            self._ngbr_dlg[sender].dispatch(evt)

            # TODO: get response from state machine
