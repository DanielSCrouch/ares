(define (problem attackvector) (:domain attacksurface)

(:objects
    placeholder - host
    bruce - host
    nigel - host
    placeholder - vuln
    CVE_2017_0143 - vuln
    CVE_2017_0146 - vuln
    CVE_2011_4885 - vuln
    CVE_2017_0148 - vuln
    CVE_2017_0146 - vuln
    CVE_2017_0144 - vuln
    CVE_2014_0195 - vuln
    CVE_2011_3368 - vuln
    CVE_2011_4885 - vuln
    CVE_2008_4250 - vuln
    CVE_2017_0144 - vuln
    CVE_2014_0224 - vuln
    CVE_2017_0147 - vuln
    CVE_2012_1823 - vuln
    CVE_2011_3368 - vuln
    CVE_2014_0195 - vuln
    CVE_2017_0148 - vuln
    CVE_2017_0147 - vuln
    CVE_2014_3566 - vuln
    CVE_2017_0145 - vuln
    CVE_2010_0425 - vuln
    CVE_2010_0425 - vuln
    CVE_2012_1823 - vuln
    CVE_2014_0224 - vuln
    CVE_2017_0145 - vuln
    CVE_2008_4114 - vuln
    CVE_2008_4114 - vuln
    CVE_2014_3566 - vuln
    CVE_2007_6750 - vuln
    CVE_2017_0143 - vuln
    CVE_2007_6750 - vuln
    CVE_2008_4250 - vuln
    placeholder - os
    )

(:init (is_host placeholder)
       (is_host bruce)
       (os_Microsoft_Windows_XP_Service_Pack_3 bruce)
       (port_scanned bruce)
       (full_scanned bruce)
       (has_tcp_port_79 bruce)
       (has_tcp_port_21 bruce)
       (has_tcp_port_80 bruce)
       (has_tcp_port_1433 bruce)
       (has_tcp_port_110 bruce)
       (has_tcp_port_25 bruce)
       (has_tcp_port_445 bruce)
       (has_tcp_port_3306 bruce)
       (has_tcp_port_139 bruce)
       (has_tcp_port_443 bruce)
       (has_CVE_2007_6750 bruce)
       (has_CVE_2008_4114 bruce)
       (has_CVE_2008_4250 bruce)
       (has_CVE_2010_0425 bruce)
       (has_CVE_2011_3368 bruce)
       (has_CVE_2011_4885 bruce)
       (has_CVE_2012_1823 bruce)
       (has_CVE_2014_0195 bruce)
       (has_CVE_2014_0224 bruce)
       (has_CVE_2014_3566 bruce)
       (has_CVE_2017_0143 bruce)
       (has_CVE_2017_0144 bruce)
       (has_CVE_2017_0145 bruce)
       (has_CVE_2017_0146 bruce)
       (has_CVE_2017_0147 bruce)
       (has_CVE_2017_0148 bruce)
       (hist_exploit_msql_brute_force bruce)
       (hist_exploit_cve_2008_4250 bruce)
       (is_host nigel)
       (os_Microsoft_Windows_XP_Service_Pack_3 nigel)
       (port_scanned nigel)
       (full_scanned nigel)
       (has_tcp_port_79 nigel)
       (has_tcp_port_21 nigel)
       (has_tcp_port_80 nigel)
       (has_tcp_port_1433 nigel)
       (has_tcp_port_110 nigel)
       (has_tcp_port_25 nigel)
       (has_tcp_port_445 nigel)
       (has_tcp_port_3306 nigel)
       (has_tcp_port_139 nigel)
       (has_tcp_port_443 nigel)
       (has_CVE_2007_6750 nigel)
       (has_CVE_2008_4114 nigel)
       (has_CVE_2008_4250 nigel)
       (has_CVE_2010_0425 nigel)
       (has_CVE_2011_3368 nigel)
       (has_CVE_2011_4885 nigel)
       (has_CVE_2012_1823 nigel)
       (has_CVE_2014_0195 nigel)
       (has_CVE_2014_0224 nigel)
       (has_CVE_2014_3566 nigel)
       (has_CVE_2017_0143 nigel)
       (has_CVE_2017_0144 nigel)
       (has_CVE_2017_0145 nigel)
       (has_CVE_2017_0146 nigel)
       (has_CVE_2017_0147 nigel)
       (has_CVE_2017_0148 nigel)
       (hist_exploit_msql_brute_force nigel)
       )

(:goal (or
    (has_progress2 bruce)
    (has_progress2 nigel)
    )
    )

)