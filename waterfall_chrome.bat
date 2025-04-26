start "" target/release/waterfall --bind_port 10000 --packet_hop 2 ^
--disable_sack --send_fake_clienthello --fc_sni yandex.ru --fake_packet_random ^
--fake_packet_override_data .gosuslugi.ru --oob_stream_hell_data .yandex.ru ^
--fake_packet_ttl 8 --disorder_packet_ttl 1 ^
--tcp_out_of_band_hell -3+s --tcp_fake_insert 3+s --tcp_out_of_band_hell 6+s ^
--fake_packet_send_http --fake_packet_host yandex.ru ^
--http_host_cmix --http_host_rmspace ^
--resist_timing_attack 15 --so_recv_size 3000 --so_send_size 16654 --so_opt_cutoff 30
