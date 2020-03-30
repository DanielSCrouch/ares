(define (problem attackvector) (:domain attacksurface)

(:objects
    placeholder - host
    bruce - host
    bruce1 - host
    bruce2 - host
    bruce3 - host
    bruce4 - host
    nigel5 - host
    placeholder - vuln
    placeholder - os
    )

(:init (is_host placeholder)
       (is_host bruce)
       (is_host bruce1)
       (is_host bruce2)
       (is_host bruce3)
       (is_host bruce4)
       (is_host nigel5)
       )

(:goal (or
    (traversed bruce)
    (traversed bruce1)
    (traversed bruce2)
    (traversed bruce3)
    (traversed bruce4)
    (traversed nigel5)
    )
    )

)