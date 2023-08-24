# @TEST-DOC: Pcap with fragmented and unordered CRYPTO frames.
#
# @TEST-EXEC: zeek -Cr $TRACES/chromium-115.0.5790.110-google-de-fragmented.pcap $PACKAGE >output
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: zeek-cut -m ts uid version cipher curve server_name resumed last_alert next_protocol established ssl_history < ssl.log > ssl.log.cut
# @TEST-EXEC: btest-diff ssl.log.cut
