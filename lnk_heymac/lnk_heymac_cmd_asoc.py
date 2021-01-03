"""
Copyright 2020 Dean Hall.  See LICENSE for details.

Data Link Layer (LNK) Heymac protocol command messages
for associating with a network
and state machines to manage the two sides of the dialog.
"""

import struct

import farc

from .lnk_heymac_cmd import HeymacCmd, HeymacCmdError



class HeymacCmdAsoc(HeymacCmd):
    """Heymac Associate: {5, sub_id, ...}

    This class should not be instantiated outside this module.
    This class serves as a base class for a range of join sub-commands.
    """
    CMD_ID = 5

    def __init__(self, *args, **kwargs):
        super().__init__(self.CMD_ID, **kwargs)

    def __bytes__(self,):
        """Serializes the join-command into bytes."""
        b = bytearray()
        b.append(HeymacCmd.PREFIX | self.CMD_ID)
        b.append(self.SUB_ID)
        if HeymacCmd.FLD_NET_ID in self.field:
            b.extend(struct.pack("!H", self.field[HeymacCmd.FLD_NET_ID]))
        if HeymacCmd.FLD_NET_ADDR in self.field:
            b.extend(struct.pack("!H", self.field[HeymacCmd.FLD_NET_ADDR]))
        return bytes(b)

    @staticmethod
    def parse(cmd_bytes):
        """Parses the bytes into a join-command object."""
        assert type(cmd_bytes) is bytes
        if len(cmd_bytes) < 2:
            raise HeymacCmdError("Insufficient data")
        if cmd_bytes[0] != (HeymacCmd.PREFIX | HeymacCmdAsoc.CMD_ID):
            raise HeymacCmdError("Incorrect CMD_ID: %d"
                                 % (cmd_bytes[0] & HeymacCmd.CMD_MASK))
        cmd = None
        for joincmd_cls in HeymacCmdAsoc.__subclasses__():
            if joincmd_cls.SUB_ID == cmd_bytes[1]:
                try:
                    if joincmd_cls.SUB_ID in (HeymacCmdAsocRqst.SUB_ID,):
                        field = {}
                        net_id = struct.unpack("!H", cmd_bytes[2:])[0]
                        field[HeymacCmd.FLD_NET_ID] = net_id
                        cmd = joincmd_cls(cmd_bytes[0], **field)
                        break
                    elif joincmd_cls.SUB_ID in (HeymacCmdAsocAcpt.SUB_ID,
                                                HeymacCmdAsocCnfm.SUB_ID):
                        field = {}
                        net_id, net_addr = struct.unpack("!HH", cmd_bytes[2:])
                        field[HeymacCmd.FLD_NET_ID] = net_id
                        field[HeymacCmd.FLD_NET_ADDR] = net_addr
                        cmd = joincmd_cls(cmd_bytes[0], **field)
                        break
                    else:
                        assert len(cmd_bytes) == 2
                        cmd = joincmd_cls()
                        break
                except struct.error:
                    raise HeymacCmdError("Incorrect data size")
                except AssertionError:
                    raise HeymacCmdError("Incorrect data size")
        if not cmd:
            raise HeymacCmdError("Unknown SUB_ID: %d" % cmd_bytes[1])
        return cmd


class HeymacCmdAsocRqst(HeymacCmdAsoc):
    """Heymac Join-Request: {5, 1, net_id}"""
    SUB_ID = 1
    _FLD_LIST = (HeymacCmd.FLD_NET_ID,)


class HeymacCmdAsocAcpt(HeymacCmdAsoc):
    """Heymac Join-Accept: {5, 2, net_id, net_addr}"""
    SUB_ID = 2
    _FLD_LIST = (HeymacCmd.FLD_NET_ID, HeymacCmd.FLD_NET_ADDR)


class HeymacCmdAsocCnfm(HeymacCmdAsoc):
    """Heymac Join-Confirm: {5, 3, net_id, net_addr}"""
    SUB_ID = 3
    _FLD_LIST = (HeymacCmd.FLD_NET_ID, HeymacCmd.FLD_NET_ADDR)


class HeymacCmdAsocRjct(HeymacCmdAsoc):
    """Heymac Join-Reject: {5, 4}"""
    SUB_ID = 4
    _FLD_LIST = ()


class HeymacCmdAsocLeav(HeymacCmdAsoc):
    """Heymac Join-Leave: {5, 5}"""
    SUB_ID = 5
    _FLD_LIST = ()


# State machines


class HeymacCmdAsocDlgInitiatorAhsm(farc.Ahsm):
    """Initiator state machine for Associate command dialog."""

    def __init__(self, ngbr_lnk_addr, net_id):
        """Class initialization."""
        super().__init__()
        self._parent_addr = ngbr_lnk_addr
        self._net_id = net_id

    @farc.Hsm.state
    def _initial(self, event):
        """PseudoState: _initial."""
        return self.tran(self._initializing)

    @farc.Hsm.state
    def _initializing(self, event):
        """State: _initializing"""
        sig = event.signal
        if sig == farc.Signal.ENTRY:
            logging.debug("LNK:CMD._initializing")
            # Build frame with AsocRqst command in the payload
            frm = lnk_frame.HeymacFrame(
                lnk_frame.HeymacFrame.PID_IDENT_HEYMAC
                | lnk_frame.HeymacFrame.PID_TYPE_CSMA,
                lnk_frame.HeymacFrame.FCTL_L
                | lnk_frame.HeymacFrame.FCTL_S
                | lnk_frame.HeymacFrame.FCTL_D)
            cmd = HeymacCmdAsocRqst(FLD_NET_ID=self._net_id)
            frm.set_field(lnk_frame.HeymacFrame.FLD_PAYLD, cmd)

            return self.handled(event)

        elif sig == farc.Signal._LNK_FRAME:
            # TODO
            return self.handled(event)

        return self.top(event)


class HeymacCmdAsocDlgResponderAhsm(farc.Ahsm):
    """Responder state machine for Join command dialog."""

    def __init__(self,):
        """Class initialization."""
        super().__init__()
