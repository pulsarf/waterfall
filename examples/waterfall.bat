start "" ../target/release/waterfall --bind_port 10000 --packet_hop 2 ^
--filter_protocol tcp --filter_port 443- --strategy_stack AB --filter_sni ntc.party --dpi_bypass_strategies tls_record_frag 7+ --reset_filter_sni ^
--filter_sni file://list_discord.txt --filter_sni file://list_youtube.txt ^
--filter_protocol tcp --filter_port 443- --strategy_stack BA --dpi_bypass_strategies tcp_disorder,tcp_split 2+,3+s auto ^
--filter_port 443- --strategy_stack AB --tls_record_frag 1+s --reset_sni_filter ^
--filter_port 80- --strategy_stack BA --dpi_bypass_strategies tcp_disorder,tcp_split 2+,6+,10+ auto ^
--filter_sni file://list_discord.txt ^
--filter_protocol udp --strategy_stack FABFBA --filter_port 443- --dpi_bypass_strategies udp_0trail,udp_meltdown auto 2+s ^
--filter_protocol udp --strategy_stack FABFBA --filter_port 50000-51000 --dpi_bypass_strategies udp_meltdown 2+s,4+s,7+s --reset_filter_sni ^
--so_recv_size 16553 --so_send_size 2000 --so_opt_cutoff 30