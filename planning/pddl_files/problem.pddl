(define (problem attackvector) (:domain attacksurface)

(:objects
    placeholder - host
    bruce - host
    nigel - host
    placeholder - vuln
    CVE_2010_0425 - vuln
    CVE_2014_3566 - vuln
    CVE_2014_0195 - vuln
    CVE_2017_0148 - vuln
    CVE_2011_3368 - vuln
    CVE_2002_1117 - vuln
    CVE_1999_0524 - vuln
    CVE_2011_3368 - vuln
    CVE_2017_0143 - vuln
    CVE_2014_0195 - vuln
    CVE_2003_1567 - vuln
    CVE_2007_6750 - vuln
    CVE_1999_0105 - vuln
    CVE_2017_0144 - vuln
    CVE_2011_4885 - vuln
    CVE_2014_0224 - vuln
    CVE_2007_6750 - vuln
    CVE_1999_0106 - vuln
    CVE_2008_4114 - vuln
    CVE_2011_4885 - vuln
    CVE_2017_0145 - vuln
    CVE_2014_0224 - vuln
    CVE_1999_0519 - vuln
    CVE_2008_4250 - vuln
    CVE_2012_1823 - vuln
    CVE_2017_0146 - vuln
    CVE_2014_3566 - vuln
    CVE_1999_0520 - vuln
    CVE_2010_0425 - vuln
    CVE_2012_1823 - vuln
    CVE_2014_3566 - vuln
    CVE_2017_0147 - vuln
    CVE_1999_0612 - vuln
    placeholder - os
    )

(:init (ishost placeholder)
       (ishost bruce)
       (scanned bruce)
       (ishost nigel)
       )

(:goal (or
    (has_progress1 bruce)
    (has_progress1 nigel)
    )
    )

)