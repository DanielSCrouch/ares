(define (problem attackvector) (:domain attacksurface)

(:objects
    placeholder - host
    t1 - host
    t2 - host
    placeholder - vuln
    CVE_2008_4114 - vuln
    CVE_2012_1823 - vuln
    CVE_2017_0143 - vuln
    CVE_2011_4885 - vuln
    CVE_2017_0146 - vuln
    CVE_2010_0425 - vuln
    CVE_2017_0144 - vuln
    CVE_2014_0195 - vuln
    CVE_2017_0148 - vuln
    CVE_2008_4250 - vuln
    CVE_2017_0147 - vuln
    CVE_2011_3368 - vuln
    CVE_2014_0224 - vuln
    CVE_2007_6750 - vuln
    CVE_2017_0145 - vuln
    CVE_2014_3566 - vuln
    placeholder - os
    )

(:init (is_host placeholder)
       (is_host t1)
       (port_scanned t1)
       (full_scanned t1)
       (initial_access t1)
       (admin_access t1)
       (os_Microsoft_Windows_XP_Service_Pack_3 t1)
       (has_tcp_port_21 t1)
       (has_tcp_port_80 t1)
       (has_tcp_port_1433 t1)
       (has_tcp_port_25 t1)
       (has_tcp_port_445 t1)
       (has_tcp_port_3306 t1)
       (has_tcp_port_139 t1)
       (has_tcp_port_443 t1)
       (has_CVE_2007_6750 t1)
       (has_CVE_2008_4114 t1)
       (has_CVE_2008_4250 t1)
       (has_CVE_2010_0425 t1)
       (has_CVE_2011_3368 t1)
       (has_CVE_2011_4885 t1)
       (has_CVE_2012_1823 t1)
       (has_CVE_2014_0195 t1)
       (has_CVE_2014_0224 t1)
       (has_CVE_2014_3566 t1)
       (has_CVE_2017_0143 t1)
       (has_CVE_2017_0144 t1)
       (has_CVE_2017_0145 t1)
       (has_CVE_2017_0146 t1)
       (has_CVE_2017_0147 t1)
       (has_CVE_2017_0148 t1)
       (has_admin_hash t1)
       (hist_exploit_cve_2008_4250 t1)
       (hist_exploit_msql_brute_force t1)
       (hist_exploit_tokens t1)
       (hist_exploit_cve_2011_2005 t1)
       (hist_exploit_hashdump t1)
       (is_host t2)
       (port_scanned t2)
       (initial_access t2)
       (admin_access t2)
       (has_tcp_port_79 t2)
       (has_tcp_port_21 t2)
       (has_tcp_port_80 t2)
       (has_tcp_port_1433 t2)
       (has_tcp_port_110 t2)
       (has_tcp_port_25 t2)
       (has_tcp_port_445 t2)
       (has_tcp_port_3306 t2)
       (has_tcp_port_139 t2)
       (has_admin_hash t2)
       (hist_exploit_msql_brute_force t2)
       (hist_exploit_psexec t2)
       )

(:goal
    (controlled t2)
    )

)