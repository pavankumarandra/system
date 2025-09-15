import os
import can
import logging
from datetime import datetime
from can.io.asc import ASCWriter
from can.util import channel2int

logger = logging.getLogger(__name__)


class CANLogger:
    def __init__(self, channel='can0', interface='socketcan', can_fd=True, filters=None, log_dir=None):
        """
        Initializes the CANLogger with the provided CAN interface settings
        and log directory.
        """
        self.channel = channel
        self.interface = interface
        self.can_fd = can_fd
        self.log_dir = log_dir
        self.filters = filters

        self.bus = None
        self.notifier = None
        self.writer = None
        self.file = None
        self.log_path = None

    def start(self, filename=None):
        """
        Start CAN bus logging with ASCWriter attached to notifier.
        """
        if self.notifier or self.writer:
            self.stop()

        os.makedirs(self.log_dir, exist_ok=True)

        # Create timestamped log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = os.path.join(self.log_dir, filename or f"can_log_{timestamp}.asc")

        try:
            # Open log file for writing
            self.file = open(self.log_path, 'w')

            # Create CAN bus interface
            self.bus = can.interface.Bus(
                channel=self.channel,
                bustype=self.interface,
                can_filters=self.filters,
                fd=self.can_fd
            )

            # Attach ASCWriter to bus via Notifier
            self.writer = ConsistentASCWriter(self.file)
            self.notifier = can.Notifier(self.bus, [self.writer])

            logging.info(f"CAN logging started: {self.log_path}")

        except Exception as e:
            logging.error(f"[CANLogger] Failed to start: {e}")

    def stop(self):
        """
        Stops logging, writes ASC footer, and generates HTML report.
        """
        try:
            if self.notifier:
                self.notifier.stop()

            if self.writer:
                self.writer.stop()

            if self.file:
                self.file.flush()
                self.file.write("End TriggerBlock\n")
                self.file.close()

            logging.info(f"CAN logging stopped: {self.log_path}")
            print(f"[CANLogger] Log file saved to: {self.log_path}")

            # --- Generate HTML Report ---
            if self.log_path:
                try:
                    from drivers.report_generator import generate_report

                    txt_file_path = os.path.join("supportfiles", "testcase.txt")
                    html_output = os.path.join(
                        "output", "html_reports",
                        os.path.basename(self.log_path).replace(".asc", ".html")
                    )

                    allowed_tx_ids = {"7A6"}
                    allowed_rx_ids = {"7AE"}

                    generate_report(
                        self.log_path,
                        txt_file_path,
                        html_output,
                        allowed_tx_ids,
                        allowed_rx_ids
                    )
                    print(f"[CANLogger] HTML report generated at: {html_output}")

                except Exception as e:
                    logging.error(f"[CANLogger] Failed to generate HTML: {e}")

        except Exception as e:
            logging.error(f"[CANLogger] Error during stop: {e}")

        # Reset
        self.bus = None
        self.notifier = None
        self.writer = None
        self.file = None

    def get_log_path(self):
        """
        Returns the path to the current log file.
        """
        return self.log_path


class ConsistentASCWriter(ASCWriter):
    """
    Consistent ASCWriter that always keeps column layout uniform.
    For CANFD frames, 'CANFD' appears as the 2nd column.
    """

    def on_message_received(self, msg):
        # Compute channel number
        channel = channel2int(msg.channel)
        if channel is None:
            channel = self.channel
        else:
            channel += 1  # 1-based

        # Handle ErrorFrame
        if msg.is_error_frame:
            serialized = f"{msg.timestamp:.6f} {channel}  ErrorFrame"
            self.log_event(serialized, msg.timestamp)
            return

        # Prepare arbitration ID
        arb_id = f"{msg.arbitration_id:X}"
        if getattr(msg, "is_extended_id", False):
            arb_id += "x"

        # Direction
        dir_str = "Rx" if getattr(msg, "is_rx", False) else "Tx"

        # DLC & data
        data_len = len(msg.data) if msg.data else 0
        dtype = f"d {data_len}"  
        data = msg.data.hex(" ").upper() if msg.data else ""


        # --- FD vs Classical ---
        if getattr(msg, "is_fd", False) and len(msg.data) > 8:
            serialized = f"{msg.timestamp:.6f} CANFD {channel} {arb_id:<15} {dir_str:<4} {dtype} {data}".rstrip()
        else:
            serialized = f"{msg.timestamp:.6f} CAN   {channel} {arb_id:<15} {dir_str:<4} {dtype} {data}".rstrip()

        self.log_event(serialized, msg.timestamp)
