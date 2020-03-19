(define (problem attackvector) (:domain attacksurface)

(:objects
    placeholder - host
    bruce - host
    placeholder - vuln
    placeholder - os
    )

(:init (is_host placeholder)
       (is_host bruce)
       (access_no_access bruce)
       (os_unknown bruce)
       )

(:goal
    (has_progress1 bruce)
    )

)