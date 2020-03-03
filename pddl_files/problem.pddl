(define (problem attackvector) (:domain attacksurface)
(:objects
	host1 - host
	host2 - host
	vuln1 - vuln
	os1 	- os
	port1 - port
	)

(:init
	(is host1)
)

(:goal (or
		(has_progress2 host1)
		(has_progress2 host2)
	)
))
