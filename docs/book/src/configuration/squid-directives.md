# Squid Directives
As previously mentioned Rama aims to be compatible with v7 of Squid Cache. Any items that are striked through are not available in v7. 
<details>
  <summary>accept_filter</summary>
  Examples:

    accept_filter httpready

    accept_filter data
</details>
<details>
  <summary>access_log</summary>
  General Format:

    access_log <module>:<place> [option ...]
</details>
<details>
  <summary>acl</summary>
  General Format:
    
    acl aclname acltype argument ...
	acl aclname acltype "file" ...
  
  Examples:

    acl localnet src 0.0.0.1-0.255.255.255	# RFC 1122 "this" network (LAN)
    acl localnet src 10.0.0.0/8		# RFC 1918 local private network (LAN)
    acl localnet src 100.64.0.0/10		# RFC 6598 shared address space (CGN)
    acl localnet src 169.254.0.0/16 	# RFC 3927 link-local (directly plugged) machines
    acl localnet src 172.16.0.0/12		# RFC 1918 local private network (LAN)
    acl localnet src 192.168.0.0/16		# RFC 1918 local private network (LAN)
    acl localnet src fc00::/7       	# RFC 4193 local private network range
    acl localnet src fe80::/10      	# RFC 4291 link-local (directly plugged) machines
    acl SSL_ports port 443
    acl Safe_ports port 80		# http
    acl Safe_ports port 21		# ftp
    acl Safe_ports port 443		# https
    acl Safe_ports port 70		# gopher
    acl Safe_ports port 210		# wais
    acl Safe_ports port 1025-65535	# unregistered ports
    acl Safe_ports port 280		# http-mgmt
    acl Safe_ports port 488		# gss-http
    acl Safe_ports port 591		# filemaker
    acl Safe_ports port 777		# multiling http

</details>
<details>
  <summary>acl_uses_indirect_client</summary>
  Controls whether the indirect client address is used instead of the direct client address in acl matching
</details>
<details>
  <summary>adaptation_access</summary>
  General Format:
    
	  adaptation_access service_name allow|deny [!]aclname...
	  adaptation_access set_name     allow|deny [!]aclname...
  Examples:
  
    adaptation_access service_1 allow all
</details>
<details>
  <summary>adaptation_masterx_shared_names</summary>
    Examples:

    adaptation_masterx_shared_names X-Subscriber-ID

</details>
<details>
  <summary>adaptation_meta</summary>
  General Format:
    
	  adaptation_meta name value [!]aclname...
  
  Examples:

    adaptation_meta X-Debug 1 needs_debugging
    adaptation_meta X-Log 1 !keep_secret
    adaptation_meta X-Authenticated-Groups "G 1" authed_as_G1
</details>
<details>
  <summary>adaptation_send_client_ip</summary>
  If enabled, Squid shares HTTP client IP information with adaptation
	services
</details>
<details>
  <summary>adaptation_send_username</summary>
  This sends authenticated HTTP client username (if available) to
	the adaptation service
</details>

<details>
  <summary>adaptation_service_chain</summary>
    General Format:
    
	  adaptation_service_chain chain_name service_name1 svc_name2 ...
  
  Examples:
    
    adaptation_service_chain svcRequest requestLogger urlFilter leakDetector
</details>
<details>
  <summary>adaptation_service_iteration_limit</summary>
    Limits the number of iterations allowed when applying adaptation
	  services to a message
</details>
<details>
  <summary>adaptation_service_set</summary>
    General Format:
    
	  adaptation_service_set set_name service_name1 service_name2 ...
  
  Examples:
    
    adaptation_service_set svcBlocker urlFilterPrimary urlFilterBackup
    adaptation service_set svcLogger loggerLocal loggerRemote
</details>

<details>
  <summary>adaptation_uses_indirect_client</summary>
  	Controls whether the indirect client IP address (instead of the direct
	  client IP address) is passed to adaptation services.

</details>
<details>
  <summary>adapted_http_access</summary>
    Allowing or Denying access based on defined access lists
</details>
<details>
  <summary>allow_underscore</summary>
    Underscore characters is not strictly allowed in Internet hostnames
    but nevertheless used by many sites
</details>
<details>
  <summary>always_direct</summary>
    General Format:
    
	    always_direct allow|deny [!]aclname ...
  
  Examples:
    
		acl local-servers dstdomain my.domain.net
		always_direct allow local-servers

</details>

<details>
  <summary><s>announce_file</s></summary>
  <p style="background-color: #fefbed; color: #d8000c; padding: 10px; border-left: 6px solid #d8000c;">
    <strong>Warning:</strong> Unsupported directive.
  </p>
</details>

<details>
  <summary><s>announce_host</s></summary>
  <p style="background-color: #fefbed; color: #d8000c; padding: 10px; border-left: 6px solid #d8000c;">
    <strong>Warning:</strong> Unsupported directive.
  </p>
</details>

<details>
  <summary><s>announce_period</s></summary>
    <p style="background-color: #fefbed; color: #d8000c; padding: 10px; border-left: 6px solid #d8000c;">
    <strong>Warning:</strong> Unsupported directive.
  </p>
</details>

<details>
  <summary><s>announce_port</s></summary>
    <p style="background-color: #fefbed; color: #d8000c; padding: 10px; border-left: 6px solid #d8000c;">
    <strong>Warning:</strong> Unsupported directive.
  </p>
</details>

<details>
  <summary>append_domain</summary>
    Examples:
		  
      append_domain .yourdomain.com
</details>

<details>
  <summary>as_whois_server</summary>
  	WHOIS server to query for AS numbers.  NOTE: AS numbers are
	  queried only when Squid starts up, not for every request.
</details>

<details>
  <summary>auth_param</summary>
</details>

<details>
  <summary>auth_schemes</summary>
</details>

<details>
  <summary>authenticate_cache_garbage_interval</summary>
  The time period between garbage collection across the username cache
</details>

<details>
  <summary><s>authenticate_ip_shortcircuit_access</s></summary>
      <p style="background-color: #fefbed; color: #d8000c; padding: 10px; border-left: 6px solid #d8000c;">
      <strong>Warning:</strong> Unsupported directive.

</details>

<details>
  <summary><s>authenticate_ip_shortcircuit_ttl</s></summary>
    <p style="background-color: #fefbed; color: #d8000c; padding: 10px; border-left: 6px solid #d8000c;">
    <strong>Warning:</strong> Unsupported directive.

</details>

<details>
  <summary>authenticate_ip_ttl</summary>
</details>

<details>
  <summary>authenticate_ttl</summary>
</details>
<details>
  <summary>background_ping_rate</summary>
</details>
<details>
  <summary>balance_on_multiple_ip</summary>
</details>
<details>
  <summary>broken_pipe</summary>
</details>
<details>
  <summary>broken_vary_encoding</summary>
</details>
<details>
  <summary>buffered_logs</summary>
</details>
<details>
  <summary>cache</summary>
</details>
<details>
  <summary>cache_dir</summary>
</details>
<details>
  <summary>cache_dns_program</summary>
</details>

<details>
  <summary>cache_effective_group</summary>
</details>

<details>
  <summary>cache_effective_user</summary>
</details>

<details>
  <summary>cache_log</summary>
</details>

<details>
  <summary>cache_log_message</summary>
</details>

<details>
  <summary>cache_mem</summary>
</details>

<details>
  <summary>cache_mgr</summary>
</details>

<details>
  <summary>cache_miss_revalidate</summary>
</details>

<details>
  <summary>cache_peer</summary>
</details>

<details>
  <summary>cache_peer_access</summary>
</details>

<details>
  <summary>cache_peer_domain</summary>
</details>

<details>
  <summary>cache_replacement_policy</summary>
</details>

<details>
  <summary>cache_store_log</summary>
</details>

<details>
  <summary>cache_swap_high</summary>
</details>

<details>
  <summary>cache_swap_log</summary>
</details>

<details>
  <summary>cache_swap_low</summary>
</details>

<details>
  <summary>cache_swap_state</summary>
</details>

<details>
  <summary>cache_vary</summary>
</details>

<details>
  <summary>cachemgr_passwd</summary>
</details>

<details>
  <summary>check_hostnames</summary>
</details>

<details>
  <summary>chroot</summary>
</details>

<details>
  <summary>chunked_request_body_max_size</summary>
</details>

<details>
  <summary>client_db</summary>
</details>

<details>
  <summary>client_delay_access</summary>
</details>

<details>
  <summary>client_delay_initial_bucket_level</summary>
</details>

<details>
  <summary>client_delay_parameters</summary>
</details>

<details>
  <summary>client_delay_pools</summary>
</details>

<details>
  <summary>client_dst_passthru</summary>
</details>

<details>
  <summary>client_idle_pconn_timeout</summary>
</details>

<details>
  <summary>client_ip_max_connections</summary>
</details>

<details>
  <summary>client_lifetime</summary>
</details>

<details>
  <summary>client_netmask</summary>
</details>

<details>
  <summary>client_persistent_connections</summary>
</details>

<details>
  <summary>client_request_buffer_max_size</summary>
</details>

<details>
  <summary>clientside_mark</summary>
</details>

<details>
  <summary>clientside_tos</summary>
</details>

<details>
  <summary>collapsed_forwarding</summary>
</details>

<details>
  <summary>collapsed_forwarding_access</summary>
</details>

<details>
  <summary>collapsed_forwarding_shared_entries_limit</summary>
</details>

<details>
  <summary>collapsed_forwarding_timeout</summary>
</details>

<details>
  <summary>configuration_includes_quoted_values</summary>
</details>

<details>
  <summary>connect_retries</summary>
</details>

<details>
  <summary>connect_timeout</summary>
</details>

<details>
  <summary>coredump_dir</summary>
</details>

<details>
  <summary>cpu_affinity_map</summary>
</details>

<details>
  <summary>dead_peer_timeout</summary>
</details>

<details>
  <summary>debug_options</summary>
</details>

<details>
  <summary>delay_access</summary>
</details>

<details>
  <summary>delay_body_max_size</summary>
</details>

<details>
  <summary>delay_class</summary>
</details>

<details>
  <summary>delay_client_reply_access</summary>
</details>

<details>
  <summary>delay_client_request_access</summary>
</details>

<details>
  <summary>delay_initial_bucket_level</summary>
</details>

<details>
  <summary>delay_parameters</summary>
</details>

<details>
  <summary>delay_pool_uses_indirect_client</summary>
</details>

<details>
  <summary>delay_pools</summary>
</details>

<details>
  <summary>deny_info</summary>
</details>

<details>
  <summary>detect_broken_pconn</summary>
</details>

<details>
  <summary>digest_bits_per_entry</summary>
</details>

<details>
  <summary>digest_generation</summary>
</details>

<details>
  <summary>digest_rebuild_chunk_percentage</summary>
</details>

I understand you're seeking further assistance in generating the toggles for the items provided. Here's the continuation for the next batch:

```html
<details>
  <summary>digest_rebuild_period</summary>
</details>

<details>
  <summary>digest_rewrite_period</summary>
</details>

<details>
  <summary>digest_swapout_chunk_size</summary>
</details>

<details>
  <summary>diskd_program</summary>
</details>

<details>
  <summary>dns_children</summary>
</details>

<details>
  <summary>dns_defnames</summary>
</details>

<details>
  <summary>dns_multicast_local</summary>
</details>

<details>
  <summary>dns_nameservers</summary>
</details>

<details>
  <summary>dns_packet_max</summary>
</details>

<details>
  <summary>dns_retransmit_interval</summary>
</details>

<details>
  <summary>dns_testnames</summary>
</details>

<details>
  <summary>dns_timeout</summary>
</details>

<details>
  <summary>dns_v4_fallback</summary>
</details>

<details>
  <summary>dns_v4_first</summary>
</details>

<details>
  <summary>ecap_enable</summary>
</details>

<details>
  <summary>ecap_service</summary>
</details>

<details>
  <summary>email_err_data</summary>
</details>

<details>
  <summary>emulate_httpd_log</summary>
</details>

<details>
  <summary>err_html_text</summary>
</details>

<details>
  <summary>err_page_stylesheet</summary>
</details>

<details>
  <summary>error_default_language</summary>
</details>

<details>
  <summary>error_directory</summary>
</details>

<details>
  <summary>error_log_languages</summary>
</details>

<details>
  <summary>error_map</summary>
</details>

<details>
  <summary>esi_parser</summary>
</details>

<details>
  <summary>eui_lookup</summary>
</details>

<details>
  <summary>extension_methods</summary>
</details>

<details>
  <summary>external_acl_type</summary>
</details>

<details>
  <summary>external_refresh_check</summary>
</details>

<details>
  <summary>follow_x_forwarded_for</summary>
</details>

<details>
  <summary>force_request_body_continuation</summary>
</details>

<details>
  <summary>forward_log</summary>
</details>

<details>
  <summary>forward_max_tries</summary>
</details>

<details>
  <summary>forward_timeout</summary>
</details>

<details>
  <summary>forwarded_for</summary>
</details>

<details>
  <summary>fqdncache_size</summary>
</details>

<details>
  <summary>ftp_client_idle_timeout</summary>
</details>

<details>
  <summary>ftp_eprt</summary>
</details>

<details>
  <summary>ftp_epsv</summary>
</details>

<details>
  <summary>ftp_epsv_all</summary>
</details>

<details>
  <summary>ftp_list_width</summary>
</details>

<details>
  <summary>ftp_passive</summary>
</details>

<details>
  <summary>ftp_port</summary>
</details>

<details>
  <summary>ftp_sanitycheck</summary>
</details>

<details>
  <summary>ftp_telnet_protocol</summary>
</details>

<details>
  <summary>ftp_user</summary>
</details>

<details>
  <summary>global_internal_static</summary>
</details>

<details>
  <summary>half_closed_clients</summary>
</details>

<details>
  <summary>happy_eyeballs_connect_gap</summary>
</details>

<details>
  <summary>happy_eyeballs_connect_limit</summary>
</details>

<details>
  <summary>happy_eyeballs_connect_timeout</summary>
</details>

<details>
  <summary>header_access</summary>
</details>

<details>
  <summary>header_replace</summary>
</details>

<details>
  <summary>hierarchy_stoplist</summary>
</details>

<details>
  <summary>high_memory_warning</summary>
</details>

<details>
  <summary>high_page_fault_warning</summary>
</details>

<details>
  <summary>high_response_time_warning</summary>
</details>

<details>
  <summary>hopeless_kid_revival_delay</summary>
</details>

<details>
  <summary>host_verify_strict</summary>
</details>

<details>
  <summary>hostname_aliases</summary>
</details>

<details>
  <summary>hosts_file</summary>
</details>
<details>
  <summary>htcp_access</summary>
</details>

<details>
  <summary>htcp_clr_access</summary>
</details>

<details>
  <summary>htcp_port</summary>
</details>

<details>
  <summary>http_accel_surrogate_remote</summary>
</details>

<details>
  <summary>http_access</summary>
</details>

<details>
  <summary>http_access2</summary>
</details>

<details>
  <summary>http_port</summary>
</details>

<details>
  <summary>http_reply_access</summary>
</details>

<details>
  <summary>http_upgrade_request_protocols</summary>
</details>

<details>
  <summary>httpd_accel_no_pmtu_disc</summary>
</details>

<details>
  <summary>httpd_accel_surrogate_id</summary>
</details>

<details>
  <summary>httpd_suppress_version_string</summary>
</details>

<details>
  <summary>https_port</summary>
</details>

<details>
  <summary>icap_206_enable</summary>
</details>

<details>
  <summary>icap_access</summary>
</details>

<details>
  <summary>icap_class</summary>
</details>

<details>
  <summary>icap_client_username_encode</summary>
</details>

<details>
  <summary>icap_client_username_header</summary>
</details>

<details>
  <summary>icap_connect_timeout</summary>
</details>

<details>
  <summary>icap_default_options_ttl</summary>
</details>

<details>
  <summary>icap_enable</summary>
</details>

<details>
  <summary>icap_io_timeout</summary>
</details>

<details>
  <summary>icap_log</summary>
</details>

<details>
  <summary>icap_persistent_connections</summary>
</details>

<details>
  <summary>icap_preview_enable</summary>
</details>

<details>
  <summary>icap_preview_size</summary>
</details>

<details>
  <summary>icap_retry</summary>
</details>

<details>
  <summary>icap_retry_limit</summary>
</details>
<details>
  <summary>icap_retry_limit</summary>
</details>

<details>
  <summary>icap_send_client_ip</summary>
</details>

<details>
  <summary>icap_send_client_username</summary>
</details>

<details>
  <summary>icap_service</summary>
</details>

<details>
  <summary>icap_service_failure_limit</summary>
</details>

<details>
  <summary>icap_service_revival_delay</summary>
</details>

<details>
  <summary>icap_uses_indirect_client</summary>
</details>

<details>
  <summary>icon_directory</summary>
</details>

<details>
  <summary>icp_access</summary>
</details>

<details>
  <summary>icp_hit_stale</summary>
</details>

<details>
  <summary>icp_port</summary>
</details>

<details>
  <summary>icp_query_timeout</summary>
</details>

<details>
  <summary>ident_lookup_access</summary>
</details>

<details>
  <summary>ident_timeout</summary>
</details>

<details>
  <summary>ie_refresh</summary>
</details>

<details>
  <summary>ignore_expect_100</summary>
</details>

<details>
  <summary>ignore_ims_on_miss</summary>
</details>

<details>
  <summary>ignore_unknown_nameservers</summary>
</details>

<details>
  <summary>incoming_dns_average</summary>
</details>

<details>
  <summary>incoming_http_average</summary>
</details>

<details>
  <summary>incoming_icp_average</summary>
</details>

<details>
  <summary>incoming_rate</summary>
</details>

<details>
  <summary>incoming_tcp_average</summary>
</details>

<details>
  <summary>incoming_udp_average</summary>
</details>

<details>
  <summary>ipcache_high</summary>
</details>

<details>
  <summary>ipcache_low</summary>
</details>

<details>
  <summary>ipcache_size</summary>
</details>

<details>
  <summary>loadable_modules</summary>
</details>

<details>
  <summary>location_rewrite_access</summary>
</details>

<details>
  <summary>location_rewrite_children</summary>
</details>

<details>
  <summary>location_rewrite_concurrency</summary>
</details>

<details>
  <summary>location_rewrite_program</summary>
</details>

<details>
  <summary>log_access</summary>
</details>

<details>
  <summary>log_fqdn</summary>
</details>

<details>
  <summary>log_icap</summary>
</details>
<details>
  <summary>log_icp_queries</summary>
</details>

<details>
  <summary>log_ip_on_direct</summary>
</details>

<details>
  <summary>log_mime_hdrs</summary>
</details>

<details>
  <summary>log_uses_indirect_client</summary>
</details>

<details>
  <summary>logfile_daemon</summary>
</details>

<details>
  <summary>logfile_rotate</summary>
</details>

<details>
  <summary>logformat</summary>
</details>

<details>
  <summary>logtype</summary>
</details>

<details>
  <summary>mail_from</summary>
</details>

<details>
  <summary>mail_program</summary>
</details>

<details>
  <summary>mark_client_connection</summary>
</details>

<details>
  <summary>mark_client_packet</summary>
</details>

<details>
  <summary>max_filedescriptors</summary>
</details>

<details>
  <summary>max_open_disk_fds</summary>
</details>

<details>
  <summary>max_stale</summary>
</details>

<details>
  <summary>maximum_icp_query_timeout</summary>
</details>

<details>
  <summary>maximum_object_size</summary>
</details>

<details>
  <summary>maximum_object_size_in_memory</summary>
</details>

<details>
  <summary>maximum_single_addr_tries</summary>
</details>

<details>
  <summary>mcast_groups</summary>
</details>

<details>
  <summary>mcast_icp_query_timeout</summary>
</details>

<details>
  <summary>mcast_miss_addr</summary>
</details>

<details>
  <summary>mcast_miss_encode_key</summary>
</details>

<details>
  <summary>mcast_miss_port</summary>
</details>

<details>
  <summary>mcast_miss_ttl</summary>
</details>

<details>
  <summary>memory_cache_mode</summary>
</details>

<details>
  <summary>memory_cache_shared</summary>
</details>

<details>
  <summary>memory_pools</summary>
</details>

<details>
  <summary>memory_pools_limit</summary>
</details>

<details>
  <summary>memory_replacement_policy</summary>
</details>

<details>
  <summary>mime_table</summary>
</details>

<details>
  <summary>min_dns_poll_cnt</summary>
</details>

<details>
  <summary>min_http_poll_cnt</summary>
</details>

<details>
  <summary>min_icp_poll_cnt</summary>
</details>

<details>
  <summary>min_tcp_poll_cnt</summary>
</details>

<details>
  <summary>min_udp_poll_cnt</summary>
</details>

<details>
  <summary>minimum_direct_hops</summary>
</details>

<details>
  <summary>minimum_direct_rtt</summary>
</details>

<details>
  <summary>minimum_expiry_time</summary>
</details>

<details>
  <summary>minimum_icp_query_timeout</summary>
</details>

<details>
  <summary>minimum_object_size</summary>
</details>

<details>
  <summary>miss_access</summary>
</details>

<details>
  <summary>negative_dns_ttl</summary>
</details>

<details>
  <summary>negative_ttl</summary>
</details>

<details>
  <summary>neighbor_type_domain</summary>
</details>

<details>
  <summary>netdb_filename</summary>
</details>

<details>
  <summary>netdb_high</summary>
</details>

<details>
  <summary>netdb_low</summary>
</details>

<details>
  <summary>netdb_ping_period</summary>
</details>

<details>
  <summary>never_direct</summary>
</details>

<details>
  <summary>nonhierarchical_direct</summary>
</details>

<details>
  <summary>note</summary>
</details>

<details>
  <summary>offline_mode</summary>
</details>

<details>
  <summary>on_unsupported_protocol</summary>
</details>

<details>
  <summary>paranoid_hit_validation</summary>
</details>

<details>
  <summary>pconn_lifetime</summary>
</details>

<details>
  <summary>pconn_timeout</summary>
</details>

<details>
  <summary>peer_connect_timeout</summary>
</details>

<details>
  <summary>persistent_connection_after_error</summary>
</details>

<details>
  <summary>persistent_request_timeout</summary>
</details>

<details>
  <summary>pid_filename</summary>
</details>
<details>
  <summary>pinger_enable</summary>
</details>

<details>
  <summary>pinger_program</summary>
</details>

<details>
  <summary>pipeline_prefetch</summary>
</details>

<details>
  <summary>positive_dns_ttl</summary>
</details>

<details>
  <summary>prefer_direct</summary>
</details>

<details>
  <summary>proxy_protocol_access</summary>
</details>

<details>
  <summary>qos_flows</summary>
</details>

<details>
  <summary>query_icmp</summary>
</details>

<details>
  <summary>quick_abort_max</summary>
</details>

<details>
  <summary>quick_abort_min</summary>
</details>

<details>
  <summary>quick_abort_pct</summary>
</details>

<details>
  <summary>range_offset_limit</summary>
</details>

<details>
  <summary>read_ahead_gap</summary>
</details>

<details>
  <summary>read_timeout</summary>
</details>

<details>
  <summary>redirector_access</summary>
</details>

<details>
  <summary>redirector_bypass</summary>
</details>

<details>
  <summary>referer_log</summary>
</details>

<details>
  <summary>refresh_all_ims</summary>
</details>

<details>
  <summary>refresh_pattern</summary>
</details>

<details>
  <summary>refresh_stale_hit</summary>
</details>

<details>
  <summary>relaxed_header_parser</summary>
</details>

<details>
  <summary>reload_into_ims</summary>
</details>

<details>
  <summary>reply_body_max_size</summary>
</details>

<details>
  <summary>reply_header_access</summary>
</details>

<details>
  <summary>reply_header_add</summary>
</details>

<details>
  <summary>reply_header_max_size</summary>
</details>

<details>
  <summary>reply_header_replace</summary>
</details>

<details>
  <summary>request_body_delay_forward_size</summary>
</details>

<details>
  <summary>request_body_max_size</summary>
</details>

<details>
  <summary>request_entities</summary>
</details>

<details>
  <summary>request_header_access</summary>
</details>

<details>
  <summary>request_header_add</summary>
</details>

<details>
  <summary>request_header_max_size</summary>
</details>

<details>
  <summary>request_header_replace</summary>
</details>

<details>
  <summary>request_start_timeout</summary>
</details>

<details>
  <summary>request_timeout</summary>
</details>

<details>
  <summary>response_delay_pool</summary>
</details>

<details>
  <summary>response_delay_pool_access</summary>
</details>

<details>
  <summary>retry_on_error</summary>
</details>

<details>
  <summary>rewrite</summary>
</details>

<details>
  <summary>rewrite_access</summary>
</details>

<details>
  <summary>send_hit</summary>
</details>

<details>
  <summary>server_http11</summary>
</details>

<details>
  <summary>server_idle_pconn_timeout</summary>
</details>

<details>
  <summary>server_pconn_for_nonretriable</summary>
</details>

<details>
  <summary>server_persistent_connections</summary>
</details>

<details>
  <summary>shared_memory_locking</summary>
</details>

<details>
  <summary>shared_transient_entries_limit</summary>
</details>

<details>
  <summary>short_icon_urls</summary>
</details>

<details>
  <summary>shutdown_lifetime</summary>
</details>

<details>
  <summary>sleep_after_fork</summary>
</details>

<details>
  <summary>snmp_access</summary>
</details>

<details>
  <summary>snmp_incoming_address</summary>
</details>

<details>
  <summary>snmp_outgoing_address</summary>
</details>

<details>
  <summary>snmp_port</summary>
</details>

<details>
  <summary>spoof_client_ip</summary>
</details>

<details>
  <summary>ssl_bump</summary>
</details>

<details>
  <summary>ssl_engine</summary>
</details>

<details>
  <summary>ssl_unclean_shutdown</summary>
</details>

<details>
  <summary>sslcrtd_children</summary>
</details>

<details>
  <summary>sslcrtd_program</summary>
</details>

<details>
  <summary>sslcrtvalidator_children</summary>
</details>

<details>
  <summary>sslcrtvalidator_children</summary>
</details>

<details>
  <summary>sslcrtvalidator_program</summary>
</details>

<details>
  <summary>sslpassword_program</summary>
</details>

<details>
  <summary>sslproxy_cafile</summary>
</details>

<details>
  <summary>sslproxy_capath</summary>
</details>

<details>
  <summary>sslproxy_cert_adapt</summary>
</details>

<details>
  <summary>sslproxy_cert_error</summary>
</details>

<details>
  <summary>sslproxy_cert_sign</summary>
</details>

<details>
  <summary>sslproxy_cert_sign_hash</summary>
</details>

<details>
  <summary>sslproxy_cipher</summary>
</details>

<details>
  <summary>sslproxy_client_certificate</summary>
</details>

<details>
  <summary>sslproxy_client_key</summary>
</details>

<details>
  <summary>sslproxy_flags</summary>
</details>

<details>
  <summary>sslproxy_foreign_intermediate_certs</summary>
</details>

<details>
  <summary>sslproxy_options</summary>
</details>

<details>
  <summary>sslproxy_session_cache_size</summary>
</details>

<details>
  <summary>sslproxy_session_ttl</summary>
</details>

<details>
  <summary>sslproxy_version</summary>
</details>

<details>
  <summary>stats_collection</summary>
</details>

<details>
  <summary>store_avg_object_size</summary>
</details>

<details>
  <summary>store_dir_select_algorithm</summary>
</details>

<details>
  <summary>store_id_access</summary>
</details>

<details>
  <summary>store_id_bypass</summary>
</details>

<details>
  <summary>store_id_children</summary>
</details>

<details>
  <summary>store_id_extras</summary>
</details>

<details>
  <summary>store_id_program</summary>
</details>

<details>
  <summary>store_miss</summary>
</details>

<details>
  <summary>store_objects_per_bucket</summary>
</details>

<details>
  <summary>storeurl_access</summary>
</details>

<details>
  <summary>storeurl_rewrite_children</summary>
</details>

<details>
  <summary>storeurl_rewrite_concurrency</summary>
</details>

<details>
  <summary>storeurl_rewrite_program</summary>
</details>

<details>
  <summary>strip_query_terms</summary>
</details>

<details>
  <summary>tcp_outgoing_address</summary>
</details>

<details>
  <summary>tcp_outgoing_mark</summary>
</details>

<details>
  <summary>tcp_outgoing_tos</summary>
</details>

<details>
  <summary>tcp_recv_bufsize</summary>
</details>

<details>
  <summary>test_reachability</summary>
</details>

<details>
  <summary>tls_key_log</summary>
</details>

<details>
  <summary>tls_outgoing_options</summary>
</details>

<details>
  <summary>tproxy_uses_indirect_client</summary>
</details>

<details>
  <summary>udp_incoming_address</summary>
</details>

<details>
  <summary>udp_outgoing_address</summary>
</details>

<details>
  <summary>umask</summary>
</details>

<details>
  <summary>unique_hostname</summary>
</details>

<details>
  <summary>unlinkd_program</summary>
</details>

<details>
  <summary>update_headers</summary>
</details>

<details>
  <summary>upgrade_http0.9</summary>
</details>

<details>
  <summary>uri_whitespace</summary>
</details>

<details>
  <summary>url_rewrite_access</summary>
</details>

<details>
  <summary>url_rewrite_bypass</summary>
</details>

<details>
  <summary>url_rewrite_children</summary>
</details>

<details>
  <summary>url_rewrite_concurrency</summary>
</details>

<details>
  <summary>url_rewrite_extras</summary>
</details>

<details>
  <summary>url_rewrite_host_header</summary>
</details>

<details>
  <summary>url_rewrite_program</summary>
</details>

<details>
  <summary>url_rewrite_timeout</summary>
</details>

<details>
  <summary>useragent_log</summary>
</details>

<details>
  <summary>vary_ignore_expire</summary>
</details>

<details>
  <summary>via</summary>
</details>
<details>
  <summary>visible_hostname</summary>
</details>

<details>
  <summary>wais_relay_host</summary>
</details>

<details>
  <summary>wais_relay_port</summary>
</details>

<details>
  <summary>wccp2_address</summary>
</details>

<details>
  <summary>wccp2_assignment_method</summary>
</details>

<details>
  <summary>wccp2_forwarding_method</summary>
</details>

<details>
  <summary>wccp2_rebuild_wait</summary>
</details>

<details>
  <summary>wccp2_return_method</summary>
</details>

<details>
  <summary>wccp2_router</summary>
</details>

<details>
  <summary>wccp2_service</summary>
</details>

<details>
  <summary>wccp2_service_info</summary>
</details>

<details>
  <summary>wccp2_weight</summary>
</details>

<details>
  <summary>wccp_address</summary>
</details>

<details>
  <summary>wccp_router</summary>
</details>

<details>
  <summary>wccp_version</summary>
</details>

<details>
  <summary>windows_ipaddrchangemonitor</summary>
</details>

<details>
  <summary>workers</summary>
</details>

<details>
  <summary>write_timeout</summary>
</details>

<details>
  <summary>zero_buffers</summary>
</details>

<details>
  <summary>zph_local</summary>
</details>

<details>
  <summary>zph_mode</summary>
</details>

<details>
  <summary>zph_option</summary>
</details>

<details>
  <summary>zph_parent</summary>
</details>

<details>
  <summary>zph_preserve_miss_tos</summary>
</details>

<details>
  <summary>zph_preserve_miss_tos_mask</summary>
</details>

<details>
  <summary>zph_sibling</summary>
</details>

<details>
  <summary>zph_tos_local</summary>
</details>

<details>
  <summary>zph_tos_parent</summary>
</details>

<details>
  <summary>zph_tos_peer</summary>
</details>
