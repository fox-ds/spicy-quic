# @TEST-REQUIRES: zeek -b -e 'print PacketAnalyzer::ANALYZER_PPP ==  PacketAnalyzer::ANALYZER_PPP'
#
# @TEST-EXEC: zeek -Cr $TRACES/interop/quic-go_quic-go/handshake.pcap $PACKAGE
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff quic.log
# @TEST-EXEC: btest-diff .stderr
