def filter(event)
    event_tmp = event.get("[enrich][tmp]")
    if event_tmp.nil?
            return [event]
    else
       ids = event_tmp.split(',')
    end
    ids.each do |item|
        key_value = item.split("#")
        if !event.get('[misp][event_id]')
            event.set('[misp][event_id]', [key_value[0]])
            event.set('[misp][type]', [key_value[1]])
        else
            event.set('[misp][event_id]', event.get('[misp][event_id]') + [key_value[0]])
            event.set('[misp][type]', event.get('[misp][type]') + [key_value[1]])
        end
    end
	return [event]
end