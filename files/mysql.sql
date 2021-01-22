SELECT dm.department_name,pt.part_name,ips.position,pt.ip_address_section,pt.ip_min,pt.ip_max,ips.ip_address_end,pt.ip_address_section||ips.ip_address_end as ip_address,ipk.lock
FROM   [ip_datas] AS [ips]
       INNER JOIN [part] AS [pt] ON [pt].[part_id] = [ips].[part_id]
       INNER JOIN [department] AS [dm] ON [pt].[department_id] = [dm].[department_id]
       left join ip_locks as ipk on ipk.part_id=ips.part_id and ipk.ip_address_end=ips.ip_address_end

