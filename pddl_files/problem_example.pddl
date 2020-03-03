(define (problem attackvector) (:domain attacksurface)
(:objects
	xx10_0_0_8 - host
	host2 	 - host
	vuln1  	 - vuln
	os1 		 - os
	port1 	 - port
	)

(:init
	(is xx10_0_0_8)
)

(:goal (or
		(has_progress2 xx10_0_0_8)
		(has_progress2 host2)
	)
))
