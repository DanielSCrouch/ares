(define (domain attacksurface)
(:requirements :adl :typing)
(:types 	host service loot 	- target
					host os port vuln 	- knowledge
					attempted failed		- history
					)

(:predicates (found           ?x - host)
						 (ishost          ?x - host)
						 (scanned			    ?x - host)
						 (has_os          ?x - os 		?y - host)
						 (has_vuln        ?x - vuln 	?y - host)
						 (has_failed	    ?x - vuln)
						 (has_progress1		?x - target)
						 (has_progress2   ?x - target)
						 )

(:action scan
:parameters   (?x - host)
:precondition (not (scanned ?x))
:effect       (and (scanned ?x)
							 		 (has_progress1 ?x))
							)
)
