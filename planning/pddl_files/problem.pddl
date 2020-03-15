(define (problem attackvector) (:domain attacksurface)

(:objects
    placeholder - host
    bruce - host
    nigel - host
    placeholder - vuln
    CVE_2010_0425 - vuln
    CVE_2002_1117 - vuln
    CVE_2014_0195 - vuln
    CVE_2011_4885 - vuln
    CVE_2012_1823 - vuln
    CVE_1999_0524 - vuln
    CVE_2011_3368 - vuln
    CVE_2003_1567 - vuln
    CVE_2017_0143 - vuln
    CVE_1999_0105 - vuln
    CVE_2014_3566 - vuln
    CVE_2017_0144 - vuln
    CVE_1999_0106 - vuln
    CVE_2014_0224 - vuln
    CVE_2017_0145 - vuln
    CVE_1999_0519 - vuln
    CVE_2007_6750 - vuln
    CVE_2008_4114 - vuln
    CVE_2017_0146 - vuln
    CVE_1999_0520 - vuln
    CVE_2017_0147 - vuln
    CVE_1999_0612 - vuln
    CVE_2008_4250 - vuln
    CVE_2017_0148 - vuln
    placeholder - os
    )

(:init (is_host placeholder)
       (is_host bruce)
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
       (has_CVE_1999_0524 bruce)
       (has_CVE_1999_0105 bruce)
       (has_CVE_1999_0106 bruce)
       (has_CVE_1999_0519 bruce)
       (has_CVE_1999_0520 bruce)
       (has_CVE_1999_0612 bruce)
       (has_CVE_2002_1117 bruce)
       (has_CVE_2003_1567 bruce)
       (is_host nigel)
       )

(:goal (or
    (has_progress1 bruce)
    (has_progress1 nigel)
    )
    )

)