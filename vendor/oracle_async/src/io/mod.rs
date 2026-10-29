pub mod packet;
pub mod codec;
pub mod ttc_reader;
pub mod ttc_writer;

pub use packet::{PacketType, RawPacket, AcceptData, build_connect_packet, parse_accept_packet, parse_refuse_error};
pub use codec::TnsCodec;
pub use ttc_reader::TtcReader;
pub use ttc_writer::TtcWriter;

use tokio::net::TcpStream;
use tokio_util::codec::Framed;

pub type TnsFramed = Framed<TcpStream, TnsCodec>;
