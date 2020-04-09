(define (problem attackvector) (:domain attacksurface)

(:objects
    placeholder - host
    t1 - host
    t2 - host
    placeholder - vuln
    placeholder - os
    )

(:init (is_host placeholder)
       (is_host t1)
       (port_scanned t1)
       (has_tcp_port_21 t1)
       (has_tcp_port_80 t1)
       (has_tcp_port_1433 t1)
       (has_tcp_port_25 t1)
       (has_tcp_port_445 t1)
       (has_tcp_port_3306 t1)
       (has_tcp_port_139 t1)
       (is_host t2)
       (port_scanned t2)
       (has_tcp_port_79 t2)
       (has_tcp_port_21 t2)
       (has_tcp_port_80 t2)
       (has_tcp_port_1433 t2)
       (has_tcp_port_110 t2)
       (has_tcp_port_25 t2)
       (has_tcp_port_445 t2)
       (has_tcp_port_3306 t2)
       (has_tcp_port_139 t2)
       )

(:goal (or
    (traversed t1)
    (traversed t2)
    )
    )

)