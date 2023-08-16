# @TEST-DOC: Pcap with dns-over-quic lookup using https://github.com/private-octopus/quicdoq
# @TEST-EXEC: zeek -Cr $TRACES/quicdoq.pcap $PACKAGE
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff quic.log
