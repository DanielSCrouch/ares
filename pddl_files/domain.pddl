(define (domain attacksurface)
(:requirements :adl :typing)
(:types 	host service loot 	- target
					host os port vuln 	- knowledge
					attempted failed		- history
					)

(:predicates (found           ?x - host)
						 (is              ?x - host)
						 (host_scanned    ?x - host)
						 (os_scanned      ?x - host)
						 (port_scanned    ?x - host)
						 (service_scanned ?x - host)
						 (full_scanned    ?x - host)
						 (has_port        ?x - port	  ?y - host)
						 (has_os          ?x - os 		?y - host)
						 (has_vuln        ?x - vuln 	?y - host)
						 (has_failed	    ?x - vuln)
						 (has_progress		?x - target)
						 (has_progress2   ?x - target)
						 )


(:action host_scan
:parameters (?x - host)
:precondition (and (not (found ?x)) (not (host_scanned ?x)))
:effect (and (found ?x)
								 			(host_scanned ?x)
								 			(has_progress ?x)))

 (:action full_scan
 	:parameters   		(?x - host)
 	:precondition 		(and (found ?x)
 									  		 (not (full_scanned ?x)))
 	:effect      		  (and (full_scanned ?x)
 									  		 (has_progress2 ?x)))
)
