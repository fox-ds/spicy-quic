# @TEST-DOC: Test that runs the pcap
# @TEST-EXEC: zeek -Cr $TRACES/quic_win11_firefox_google.pcap $PACKAGE >output
# @TEST-EXEC: btest-diff conn.log
