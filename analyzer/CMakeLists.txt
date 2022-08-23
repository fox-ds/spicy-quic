spicy_add_analyzer(
    NAME QUIC
    PACKAGE_NAME QUIC
    SOURCES QUIC.spicy QUIC.evt zeek_QUIC.spicy
    SCRIPTS __load__.zeek main.zeek)
