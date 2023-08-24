# @TEST-DOC: Test that runs the pcap
# @TEST-EXEC: zeek -Cr $TRACES/curl-8.1.2-dev-http3-www-google-de.pcap $PACKAGE
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff quic.log
